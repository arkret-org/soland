use std::collections::BTreeMap;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use contrix_sdk::{ErrorEnvelope, ServerDescription, SpaceSearchEntry};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::artifacts;

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct HealthResponse {
    pub ok: bool,
    pub service: &'static str,
    pub storage: &'static str,
    pub checks: Value,
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
pub struct SyncDescribeResponse {
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
pub struct RegisterSchemaRequest {
    pub schema_id: String,
    pub kind: String,
    pub version: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub definition: Value,
    #[serde(default = "default_true")]
    pub active: bool,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct SchemaResponse {
    pub schema_id: String,
    pub kind: String,
    pub version: String,
    pub name: Option<String>,
    pub owner: String,
    pub definition: Value,
    pub active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct SchemasResponse {
    pub schemas: Vec<SchemaResponse>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct SearchSpacesRequest {
    pub query: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct DirectoryDescribeResponse {
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
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct ResolveHandleRequest {
    pub handle: String,
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
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct IndexQueryRequest {
    #[serde(default)]
    pub space_ids: Vec<String>,
    #[serde(default)]
    pub entity_types: Vec<String>,
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
    #[serde(default)]
    pub entity_types: Vec<String>,
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
pub struct IndexEntityResponse {
    pub entity: Value,
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
pub struct BackfillResponse {
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
pub struct EventsFrontierResponse {
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
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct RepoDescribeResponse {
    pub repo_did: String,
    pub head_commit: Option<String>,
    pub supported_signatures: Vec<String>,
    pub limits: Value,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct ListCommitsResponse {
    pub commits: Vec<Value>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct GetOperationsRequest {
    #[serde(default)]
    pub operation_ids: Vec<String>,
    #[serde(default = "default_include_payload")]
    pub include_payload: bool,
}

fn default_include_payload() -> bool {
    true
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct GetOperationsResponse {
    pub operations: Vec<Value>,
    pub missing: Vec<String>,
    pub unauthorized: Vec<String>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct RepoSyncRequest {
    pub repo_id: String,
    pub since: Option<String>,
    pub limit: Option<usize>,
    #[serde(default)]
    pub filters: Option<Value>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct RepoSyncResponse {
    pub operations: Vec<Value>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct SubmitCommitRequest {
    pub repo_id: String,
    pub commit: Value,
    #[serde(default)]
    pub operations: Vec<Value>,
    pub expected_head: Option<String>,
    pub idempotency_key: Option<String>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct SubmitCommitResponse {
    pub status: String,
    pub commit_id: String,
    pub head_commit: Option<String>,
    pub sync_token: String,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct AuthzCheckRequest {
    pub actor: String,
    pub action: String,
    pub resource: Value,
    #[serde(default)]
    pub context: Option<Value>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct AuthzCheckResponse {
    pub allowed: bool,
    pub reason_code: Option<String>,
    pub reason: Option<String>,
    pub grants: Vec<Value>,
    pub obligations: Vec<Value>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct EffectiveGrantsResponse {
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
pub struct PushNotifyRequest {
    pub notification: Value,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct PushNotifyResponse {
    pub rejected: Vec<Value>,
}

fn default_true() -> bool {
    true
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
pub struct OkResponse {
    pub ok: bool,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct ModerationReportRequest {
    pub space_id: String,
    pub target_ref: String,
    pub reason: String,
    pub reporter: String,
    pub description: Option<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct ModerationReportResponse {
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
pub struct PolicyCheckRequest {
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
pub struct PolicyCheckResponse {
    pub decision: String,
    pub reason_code: String,
    pub policy_id: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub obligations: Vec<Value>,
    pub signature: Value,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct ApiError {
    pub ok: bool,
    pub error: ErrorEnvelope,
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
    #[serde(default)]
    pub plaintext_visible_services: Vec<String>,
    #[serde(default)]
    pub invitees: Vec<String>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct AddSpaceMemberRequest {
    pub member: String,
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
pub struct SendMessageResponse {
    pub event_id: String,
    pub operation_id: String,
    pub commit_id: String,
    pub head_commit: Option<String>,
    pub sync_token: String,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct IdentityDescribeResponse {
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
pub struct IdentityResolveRequest {
    pub did: String,
    #[serde(default)]
    pub include: Vec<String>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct SubmitDidOperationRequest {
    pub did: String,
    pub seq: u64,
    #[serde(default)]
    pub prev_event_hash: Option<String>,
    pub patch: Value,
    #[serde(default)]
    pub proofs: Vec<Value>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct SubmitDidOperationResponse {
    pub status: String,
    pub head_event_hash: String,
    pub seq: u64,
    pub receipts: Vec<Value>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct IdentityLogResponse {
    pub events: Vec<Value>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct IdentityReceiptsResponse {
    pub receipts: Vec<Value>,
    pub threshold_met: bool,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct IdentityResolveResponse {
    pub did_document: Value,
    pub key_log_head: Option<String>,
    pub seq: u64,
    pub receipts: Vec<Value>,
    pub method_evidence: Value,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct KeysUploadRequest {
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
pub struct KeysUploadResponse {
    pub one_time_key_counts: Value,
    pub fallback_keys: Value,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct KeysQueryRequest {
    pub device_keys: std::collections::BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct KeysQueryResponse {
    pub device_keys: Value,
    pub failures: Value,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct KeysClaimRequest {
    pub one_time_keys:
        std::collections::BTreeMap<String, std::collections::BTreeMap<String, String>>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct KeysClaimResponse {
    pub one_time_keys: Value,
    pub failures: Value,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct KeysBackupsPutResponse {
    pub ok: bool,
    pub backup: Value,
    pub state: String,
    #[serde(default)]
    pub todos: Vec<String>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct KeysBackupsListResponse {
    pub backups: Vec<Value>,
    pub next_cursor: Option<String>,
    pub state: String,
    #[serde(default)]
    pub todos: Vec<String>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct KeysBackupsDeleteResponse {
    pub ok: bool,
    pub backup_id: String,
    pub deleted: bool,
    pub state: String,
    #[serde(default)]
    pub todos: Vec<String>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct DeviceMessagesSendRequest {
    pub messages: std::collections::BTreeMap<String, std::collections::BTreeMap<String, Value>>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct DeviceMessagesSendResponse {
    pub ok: bool,
    pub delivered: Value,
    pub unknown_devices: Value,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct DeviceMessagesReceiveResponse {
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
pub struct BlobUploadResponse {
    pub blob_ref: String,
    pub size: usize,
    pub media_type: String,
    pub sha256: String,
    pub upload_receipt: Value,
}

pub fn describe(
    service_did: &str,
    storage: &'static str,
    development_mode: bool,
    oauth_introspection_enabled: bool,
) -> ServerDescription {
    let mut supported_auth_methods = Vec::new();
    if development_mode {
        supported_auth_methods.push("dev_bearer_token");
    }
    if oauth_introspection_enabled {
        supported_auth_methods.push("oauth2_bearer_introspection");
    }

    ServerDescription {
        service_did: service_did.parse().expect("valid service DID"),
        service_type: "principal_server".to_owned(),
        protocol_version: "1.0".to_owned(),
        supported_profiles: vec![
            "cx.profile.soland_limited_server.v1".to_owned(),
            "cx.profile.mimi_interop.v1".to_owned(),
        ],
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
            "repo.submit_commit".to_owned(),
            "repo.read".to_owned(),
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
        supported_operations: vec![
            "cx.repo.describe".to_owned(),
            "cx.account.register".to_owned(),
            "cx.account.me".to_owned(),
            "cx.auth.logout".to_owned(),
            "cx.contacts.request".to_owned(),
            "cx.contacts.respond".to_owned(),
            "cx.contacts.list".to_owned(),
            "cx.spaces.create".to_owned(),
            "cx.spaces.add_member".to_owned(),
            "cx.spaces.remove_member".to_owned(),
            "cx.spaces.delete".to_owned(),
            "cx.messages.send".to_owned(),
            "cx.schemas.list".to_owned(),
            "cx.schemas.get".to_owned(),
            "cx.schemas.register".to_owned(),
            "cx.schemas.delete".to_owned(),
            "cx.events.describe".to_owned(),
            "cx.events.submit".to_owned(),
            "cx.events.get".to_owned(),
            "cx.events.batch_get".to_owned(),
            "cx.events.query".to_owned(),
            "cx.events.subscribe".to_owned(),
            "cx.events.frontier".to_owned(),
            "cx.repo.list_commits".to_owned(),
            "cx.repo.get_operations".to_owned(),
            "cx.repo.sync".to_owned(),
            "cx.repo.submit_commit".to_owned(),
            "cx.federation.transaction".to_owned(),
            "cx.federation.push_operations".to_owned(),
            "cx.federation.pull_operations".to_owned(),
            "cx.federation.space_members".to_owned(),
            "cx.federation.verify_actor".to_owned(),
            "cx.sync.account".to_owned(),
            "cx.sync.typing".to_owned(),
            "cx.sync.get_snapshot_head".to_owned(),
            "cx.directory.describe".to_owned(),
            "cx.directory.search_spaces".to_owned(),
            "cx.directory.resolve_space".to_owned(),
            "cx.index.describe".to_owned(),
            "cx.index.query".to_owned(),
            "cx.authz.check".to_owned(),
            "cx.authz.get_effective_grants".to_owned(),
            "cx.authz.get_invites".to_owned(),
            "cx.push.register_device".to_owned(),
            "cx.push.unregister_device".to_owned(),
            "cx.push.rules".to_owned(),
            "cx.push.notify".to_owned(),
            "cx.webrtc.create_session".to_owned(),
            "cx.webrtc.send_signal".to_owned(),
            "cx.webrtc.get_signals".to_owned(),
            "cx.webrtc.close_session".to_owned(),
            "cx.policies.list".to_owned(),
            "cx.policies.get".to_owned(),
            "cx.policies.upsert".to_owned(),
            "cx.policies.delete".to_owned(),
            "cx.policy.check".to_owned(),
            "cx.receipt.read".to_owned(),
            "cx.moderation.report".to_owned(),
            "cx.mimi.provider_directory".to_owned(),
            "cx.mimi.key_material".to_owned(),
            "cx.mimi.room_update".to_owned(),
            "cx.mimi.notify".to_owned(),
            "cx.mimi.submit_message".to_owned(),
            "cx.mimi.group_info".to_owned(),
            "cx.mimi.request_consent".to_owned(),
            "cx.mimi.update_consent".to_owned(),
            "cx.mimi.identifier_query".to_owned(),
            "cx.mimi.report_abuse".to_owned(),
            "cx.mimi.proxy_download".to_owned(),
        ],
        supported_bindings: vec![serde_json::json!({"kind": "http_json", "base_path": "/api/v1"})],
        supported_reducer_profiles: vec!["cx.reducer.v1".to_owned()],
        supported_schema_profiles: vec!["cx.schema.core.v1".to_owned()],
        auth_metadata: serde_json::json!({
            "mode": if development_mode { "development" } else { "production" },
            "supported_auth_methods": supported_auth_methods,
        }),
        limits: serde_json::json!({
            "storage": storage,
            "max_limit": 100,
            "registries": artifacts::registry_summary(),
            "plaintext_visible_service_capability": {
                "supported": true,
                "service_did": service_did,
                "enforced_on": [
                    "repo.submit_commit",
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
                "full_profiles_not_claimed": [
                    "cx.profile.principal_server.v1",
                    "cx.profile.principal_server_repo_api.v1",
                    "cx.profile.index_node.v1",
                    "cx.profile.identity_registry.v1",
                    "cx.profile.blob_node.v1"
                ],
                "implemented_surfaces": [
                    "principal_server",
                    "events_api_minimal",
                    "repo_api",
                    "sync",
                    "index",
                    "identity_registry_local_dev",
                    "blob_node_local",
                    "directory_service",
                    "mimi_provider_facade"
                ],
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
    let cursor = json!({
        "schema": "cx.schema.cursor.v1",
        "version": 1,
        "profile": "incremental",
        "issued_at": now,
        "issued_at_ms": now.timestamp_millis(),
        "positions": {
            "spaces": {},
            "devices": {},
            "repo": null
        }
    });
    format!("cx:cursor:{}", URL_SAFE_NO_PAD.encode(cursor.to_string()))
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
    pub commit_id: String,
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

// ── Entity/Relation/View DTOs ──

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct CreateEntityRequest {
    pub space_id: String,
    pub entity_type: String,
    #[serde(default)]
    pub facets: Value,
    pub title: Option<String>,
    pub content: Option<Value>,
    #[serde(default)]
    pub fields: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, salvo::oapi::ToSchema)]
pub struct EntityResponse {
    pub entity_id: String,
    pub space_id: String,
    pub entity_type: String,
    pub facets: Vec<String>,
    pub title: Option<String>,
    pub content: Option<Value>,
    pub fields: BTreeMap<String, Value>,
    pub deleted: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct UpdateEntityRequest {
    pub title: Option<String>,
    pub content: Option<Value>,
    #[serde(default)]
    pub facets: Option<Value>,
    #[serde(default)]
    pub fields: BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct ListEntitiesRequest {
    pub space_id: String,
    pub entity_type: Option<String>,
}

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

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct CreateViewRequest {
    pub space_id: String,
    pub kind: String,
    pub title: Option<String>,
    pub entity_type: Option<String>,
    #[serde(default)]
    pub options: Value,
}

#[derive(Debug, Deserialize, salvo::oapi::ToSchema)]
pub struct CreateGrantRequest {
    pub space_id: String,
    pub subject: String,
    pub resource: String,
    pub actions: Vec<String>,
    #[serde(default)]
    pub constraints: Vec<serde_json::Value>,
}

#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
pub struct ViewResponse {
    pub view_id: String,
    pub space_id: String,
    pub kind: String,
    pub title: Option<String>,
    pub entities: Vec<EntityResponse>,
    pub projection: Value,
    pub created_at: String,
}
