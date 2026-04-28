use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use contrix_sdk::{Commit, ErrorEnvelope, Operation, ServerDescription, SpaceSearchEntry};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub ok: bool,
    pub service: &'static str,
    pub storage: &'static str,
}

#[derive(Debug, Serialize)]
pub struct SyncDescribeResponse {
    pub service_did: String,
    pub supported_sync_profiles: Vec<String>,
    pub limits: Value,
    pub frontier: Value,
}

#[derive(Debug, Deserialize)]
pub struct ClientSyncRequest {
    pub since: Option<String>,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    #[serde(default)]
    pub filter: Option<Value>,
    #[serde(default)]
    pub set_presence: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Debug, Deserialize)]
pub struct SearchSpacesRequest {
    pub query: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct DirectoryDescribeResponse {
    pub service_did: String,
    pub resource_types: Vec<String>,
    pub discovery_profiles: Vec<String>,
    pub restricted_query_proof: bool,
}

#[derive(Debug, Deserialize)]
pub struct ResolveSpaceRequest {
    pub space_id: Option<String>,
    pub alias: Option<String>,
    pub invite_token: Option<String>,
    pub signed_link: Option<String>,
    #[serde(default)]
    pub requester: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ResolveSpaceResponse {
    pub space_preview: SpaceSearchEntry,
    pub stripped_state: Vec<Value>,
    pub join_rule: String,
    pub via_services: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct SearchSpacesResponse {
    pub results: Vec<SpaceSearchEntry>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SearchOrganizationsRequest {
    pub query: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub struct ResolveOrganizationRequest {
    pub organization_id: Option<String>,
    pub handle: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SearchActorsRequest {
    pub query: Option<String>,
    pub organization_id: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub struct ResolveHandleRequest {
    pub handle: String,
}

#[derive(Debug, Serialize)]
pub struct DirectoryValueSearchResponse {
    pub results: Vec<Value>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ResolveOrganizationResponse {
    pub organization: Value,
    pub spaces: Vec<Value>,
}

#[derive(Debug, Serialize)]
pub struct ResolveHandleResponse {
    pub handle: String,
    pub did: String,
    pub actor: Value,
}

#[derive(Debug, Deserialize)]
pub struct IndexQueryRequest {
    #[serde(default)]
    pub space_ids: Vec<String>,
    #[serde(default)]
    pub entity_types: Vec<String>,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct IndexQueryResponse {
    pub results: Vec<Value>,
    pub next_cursor: Option<String>,
    pub frontier: Value,
}

#[derive(Debug, Serialize)]
pub struct IndexDescribeResponse {
    pub service_did: String,
    pub reducer_profiles: Vec<String>,
    pub schema_profiles: Vec<String>,
    pub query_features: Vec<String>,
    pub frontier: Value,
}

#[derive(Debug, Deserialize)]
pub struct IndexSearchRequest {
    pub query: String,
    #[serde(default)]
    pub space_ids: Vec<String>,
    #[serde(default)]
    pub entity_types: Vec<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct IndexSearchResponse {
    pub results: Vec<Value>,
    pub next_cursor: Option<String>,
    pub frontier: Value,
}

#[derive(Debug, Serialize)]
pub struct IndexEntityResponse {
    pub entity: Value,
    pub frontier: Value,
}

#[derive(Debug, Serialize)]
pub struct IndexThreadResponse {
    pub thread: Value,
    pub events: Vec<Value>,
    pub next_cursor: Option<String>,
    pub frontier: Value,
}

#[derive(Debug, Serialize)]
pub struct IndexNotificationsResponse {
    pub notifications: Vec<Value>,
    pub next_cursor: Option<String>,
    pub unread_count: usize,
    pub frontier: Value,
}

#[derive(Debug, Serialize)]
pub struct IndexInboxResponse {
    pub rooms: Vec<Value>,
    pub next_cursor: Option<String>,
    pub frontier: Value,
}

#[derive(Debug, Serialize)]
pub struct IndexSpaceHierarchyResponse {
    pub root_space_id: String,
    pub spaces: Vec<Value>,
    pub edges: Vec<Value>,
    pub frontier: Value,
}

#[derive(Debug, Serialize)]
pub struct BackfillResponse {
    pub events: Vec<Value>,
    pub prev_cursor: Option<String>,
    pub next_cursor: Option<String>,
    pub limited: bool,
}

#[derive(Debug, Serialize)]
pub struct SnapshotHeadResponse {
    pub snapshot_ref: String,
    pub state_hash: String,
    pub frontier: Value,
    pub signature: Value,
}

#[derive(Debug, Serialize)]
pub struct RepoDescribeResponse {
    pub repo_did: String,
    pub head_commit: Option<String>,
    pub supported_signatures: Vec<String>,
    pub limits: Value,
}

#[derive(Debug, Serialize)]
pub struct ListCommitsResponse {
    pub commits: Vec<Commit>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[derive(Debug, Deserialize)]
pub struct GetOperationsRequest {
    #[serde(default)]
    pub operation_ids: Vec<String>,
    #[serde(default = "default_include_payload")]
    pub include_payload: bool,
}

fn default_include_payload() -> bool {
    true
}

#[derive(Debug, Serialize)]
pub struct GetOperationsResponse {
    pub operations: Vec<Operation>,
    pub missing: Vec<String>,
    pub unauthorized: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct RepoSyncRequest {
    pub repo_id: String,
    pub since: Option<String>,
    pub limit: Option<usize>,
    #[serde(default)]
    pub filters: Option<Value>,
}

#[derive(Debug, Serialize)]
pub struct RepoSyncResponse {
    pub operations: Vec<Operation>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[derive(Debug, Deserialize)]
pub struct SubmitCommitRequest {
    pub repo_id: String,
    pub commit: Commit,
    #[serde(default)]
    pub operations: Vec<Operation>,
    pub expected_head: Option<String>,
    pub idempotency_key: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SubmitCommitResponse {
    pub status: String,
    pub commit_id: String,
    pub head_commit: Option<String>,
    pub sync_token: String,
}

#[derive(Debug, Deserialize)]
pub struct AuthzCheckRequest {
    pub actor: String,
    pub action: String,
    pub resource: Value,
    #[serde(default)]
    pub context: Option<Value>,
}

#[derive(Debug, Serialize)]
pub struct AuthzCheckResponse {
    pub allowed: bool,
    pub reason_code: Option<String>,
    pub grants: Vec<Value>,
    pub obligations: Vec<Value>,
}

#[derive(Debug, Serialize)]
pub struct EffectiveGrantsResponse {
    pub grants: Vec<Value>,
    pub state_hash: Option<String>,
    pub evaluated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct InvitesResponse {
    pub invites: Vec<Value>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PushRegisterRequest {
    pub device_id: String,
    pub push_gateway: String,
    pub push_key: String,
    pub platform: Option<String>,
    pub app_id: Option<String>,
    pub display_name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PushRegisterResponse {
    pub ok: bool,
    pub registration_id: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
pub struct PushUnregisterRequest {
    pub device_id: String,
    pub push_key: Option<String>,
    pub app_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PushNotifyRequest {
    pub notification: Value,
}

#[derive(Debug, Serialize)]
pub struct PushNotifyResponse {
    pub rejected: Vec<Value>,
}

#[derive(Debug, Serialize)]
pub struct OkResponse {
    pub ok: bool,
}

#[derive(Debug, Deserialize)]
pub struct ModerationReportRequest {
    pub space_id: String,
    pub target_ref: String,
    pub reason: String,
    pub reporter: String,
    pub description: Option<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ModerationReportResponse {
    pub report_id: String,
    pub status: String,
    pub routed_to: Vec<String>,
}

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Serialize)]
pub struct PolicyCheckResponse {
    pub decision: String,
    pub reason_code: String,
    pub expires_at: DateTime<Utc>,
    pub obligations: Vec<Value>,
    pub signature: Value,
}

#[derive(Debug, Serialize)]
pub struct ApiError {
    pub ok: bool,
    pub error: ErrorEnvelope,
}

#[derive(Debug, Deserialize)]
pub struct DevLoginRequest {
    pub actor: String,
    pub device_id: String,
    pub display_name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DevLoginResponse {
    pub access_token: String,
    pub token_type: String,
    pub actor: String,
    pub device_id: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct LogoutResponse {
    pub ok: bool,
    pub revoked: bool,
}

#[derive(Debug, Deserialize)]
pub struct RegisterAccountRequest {
    pub did: String,
    pub handle: String,
    pub display_name: Option<String>,
    pub device_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AccountResponse {
    pub did: String,
    pub handle: String,
    pub display_name: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct ContactRequestRequest {
    pub target: String,
}

#[derive(Debug, Deserialize)]
pub struct ContactRespondRequest {
    pub requester: String,
    pub action: String,
}

#[derive(Debug, Serialize)]
pub struct ContactResponse {
    pub requester: String,
    pub target: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct ContactsResponse {
    pub contacts: Vec<ContactResponse>,
}

#[derive(Debug, Deserialize)]
pub struct CreateSpaceRequest {
    pub title: String,
    pub summary: Option<String>,
    #[serde(default)]
    pub public: bool,
    #[serde(default)]
    pub invitees: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct AddSpaceMemberRequest {
    pub member: String,
}

#[derive(Debug, Serialize)]
pub struct SpaceLifecycleResponse {
    pub ok: bool,
    pub space_id: String,
    pub owner: String,
    pub members: Vec<String>,
    pub deleted: bool,
}

#[derive(Debug, Deserialize)]
pub struct SendMessageRequest {
    pub space_id: String,
    #[serde(default)]
    pub thread_id: Option<String>,
    pub content: Value,
    #[serde(default)]
    pub encrypted: bool,
}

#[derive(Debug, Serialize)]
pub struct SendMessageResponse {
    pub event_id: String,
    pub operation_id: String,
    pub commit_id: String,
    pub head_commit: Option<String>,
    pub sync_token: String,
}

#[derive(Debug, Serialize)]
pub struct IdentityDescribeResponse {
    pub service_did: String,
    pub registry_mode: String,
    pub supported_receipts: Vec<String>,
    pub protocol_version: String,
    pub profiles: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct IdentityResolveRequest {
    pub did: String,
    #[serde(default)]
    pub include: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct SubmitDidOperationRequest {
    pub did: String,
    pub seq: u64,
    #[serde(default)]
    pub prev_event_hash: Option<String>,
    pub patch: Value,
    #[serde(default)]
    pub proofs: Vec<Value>,
}

#[derive(Debug, Serialize)]
pub struct SubmitDidOperationResponse {
    pub status: String,
    pub head_event_hash: String,
    pub seq: u64,
    pub receipts: Vec<Value>,
}

#[derive(Debug, Serialize)]
pub struct IdentityLogResponse {
    pub events: Vec<Value>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[derive(Debug, Serialize)]
pub struct IdentityReceiptsResponse {
    pub receipts: Vec<Value>,
    pub threshold_met: bool,
}

#[derive(Debug, Serialize)]
pub struct IdentityResolveResponse {
    pub did_document: Value,
    pub key_log_head: Option<String>,
    pub seq: u64,
    pub receipts: Vec<Value>,
    pub method_evidence: Value,
}

#[derive(Debug, Deserialize)]
pub struct KeysUploadRequest {
    pub device_id: String,
    #[serde(default)]
    pub device_keys: Value,
    #[serde(default)]
    pub one_time_keys: Vec<Value>,
    #[serde(default)]
    pub fallback_keys: Value,
    #[serde(default)]
    pub mls_key_packages: Vec<Value>,
    #[serde(default)]
    pub device_signature: Value,
}

#[derive(Debug, Serialize)]
pub struct KeysUploadResponse {
    pub one_time_key_counts: Value,
    pub fallback_keys: Value,
}

#[derive(Debug, Deserialize)]
pub struct KeysQueryRequest {
    pub device_keys: std::collections::BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct KeysQueryResponse {
    pub device_keys: Value,
    pub failures: Value,
}

#[derive(Debug, Deserialize)]
pub struct KeysClaimRequest {
    pub one_time_keys:
        std::collections::BTreeMap<String, std::collections::BTreeMap<String, String>>,
}

#[derive(Debug, Serialize)]
pub struct KeysClaimResponse {
    pub one_time_keys: Value,
    pub failures: Value,
}

#[derive(Debug, Deserialize)]
pub struct DeviceMessagesSendRequest {
    pub messages: std::collections::BTreeMap<String, std::collections::BTreeMap<String, Value>>,
}

#[derive(Debug, Serialize)]
pub struct DeviceMessagesSendResponse {
    pub ok: bool,
    pub delivered: Value,
    pub unknown_devices: Value,
}

#[derive(Debug, Serialize)]
pub struct DeviceMessagesReceiveResponse {
    pub events: Vec<Value>,
    pub next_batch: Option<String>,
    pub limited: bool,
}

#[derive(Debug, Serialize)]
pub struct BlobUploadResponse {
    pub blob_ref: String,
    pub size: usize,
    pub media_type: String,
    pub sha256: String,
    pub upload_receipt: Value,
}

pub fn describe(storage: &'static str) -> ServerDescription {
    ServerDescription {
        service_did: "did:web:serverx.local".parse().expect("valid did"),
        service_type: "principal_server".to_owned(),
        protocol_version: "1.0".to_owned(),
        supported_profiles: vec!["cx.schema.core.v1".to_owned(), "cx.reducer.v1".to_owned()],
        supported_features: vec![
            "account.register".to_owned(),
            "account.me".to_owned(),
            "auth.logout".to_owned(),
            "contacts.request".to_owned(),
            "contacts.respond".to_owned(),
            "space.lifecycle".to_owned(),
            "messages.send".to_owned(),
            "repo.submit_commit".to_owned(),
            "repo.read".to_owned(),
            "federation.transaction".to_owned(),
            "federation.operations".to_owned(),
            "sync.client_sync".to_owned(),
            "sync.backfill".to_owned(),
            "directory.search_spaces".to_owned(),
            "directory.resolve_space".to_owned(),
            "index.query".to_owned(),
            "authz.check".to_owned(),
            "profile.presence".to_owned(),
            "push.register_device".to_owned(),
            "moderation.report".to_owned(),
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
            "cx.repo.list_commits".to_owned(),
            "cx.repo.get_operations".to_owned(),
            "cx.repo.sync".to_owned(),
            "cx.repo.submit_commit".to_owned(),
            "cx.federation.transaction".to_owned(),
            "cx.federation.push_operations".to_owned(),
            "cx.federation.pull_operations".to_owned(),
            "cx.federation.space_members".to_owned(),
            "cx.federation.verify_actor".to_owned(),
            "cx.sync.client_sync".to_owned(),
            "cx.sync.backfill".to_owned(),
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
            "cx.push.notify".to_owned(),
            "cx.policy.check".to_owned(),
            "cx.moderation.report".to_owned(),
        ],
        supported_bindings: vec![serde_json::json!({"kind": "http_json", "base_path": "/api/v1"})],
        supported_reducer_profiles: vec!["cx.reducer.v1".to_owned()],
        supported_schema_profiles: vec!["cx.schema.core.v1".to_owned()],
        auth_metadata: serde_json::json!({"mode": "development"}),
        limits: serde_json::json!({"storage": storage, "max_limit": 100}),
    }
}

pub fn sync_token() -> String {
    format!("sx:{}", Utc::now().timestamp_millis())
}

pub fn now() -> DateTime<Utc> {
    Utc::now()
}
