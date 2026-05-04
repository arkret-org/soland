use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::{Arc, Mutex},
};

use contrix_sdk::{
    Did, Operation, SpaceId, SpaceSearchEntry, SpaceSearchIndex,
    identity::{CompositeDidResolver, DidKeyResolver, DidUuidResolver, DidWebResolver},
};
use serde_json::{Value, json};

use crate::artifacts;
use crate::authz::AuthzEngine;
use crate::config::AppConfig;
use crate::db::Db;
use crate::hlc::ServerHlc;
use crate::persistence::{MemoryPersistenceStore, PersistenceStore, PgPersistenceStore};
use crate::reducer::ProjectionState;
use crate::repo::{MemoryRepoAdapter, PgRepoAdapter, RepoAdapterRef};

type OneTimeKeyStore = Arc<Mutex<BTreeMap<(String, String), Vec<Value>>>>;

#[derive(Clone)]
pub struct AppState {
    pub config: AppConfig,
    pub db: Db,
    pub repo: RepoAdapterRef,
    pub persistence: Arc<dyn PersistenceStore>,
    pub hlc: ServerHlc,
    pub projection: Arc<Mutex<ProjectionState>>,
    pub authz: AuthzEngine,
    pub spaces: Arc<Mutex<SpaceSearchIndex>>,
    pub space_meta: Arc<Mutex<BTreeMap<String, SpaceMetaRecord>>>,
    pub schemas: Arc<Mutex<BTreeMap<String, SchemaRecord>>>,
    pub accounts: Arc<Mutex<BTreeMap<String, AccountRecord>>>,
    pub identity_documents: Arc<Mutex<BTreeMap<String, IdentityDocumentRecord>>>,
    pub identity_log_events: Arc<Mutex<BTreeMap<String, Vec<IdentityLogRecord>>>>,
    pub did_resolver: Arc<Mutex<CompositeDidResolver>>,
    pub contacts: Arc<Mutex<BTreeMap<(String, String), ContactRecord>>>,
    pub space_invites: Arc<Mutex<BTreeMap<String, SpaceInviteRecord>>>,
    pub sessions: Arc<Mutex<BTreeMap<String, SessionRecord>>>,
    pub messages: Arc<Mutex<Vec<MessageRecord>>>,
    pub events: Arc<Mutex<BTreeMap<String, CanonicalEventRecord>>>,
    pub projection_events: Arc<Mutex<Vec<ProjectionEventRecord>>>,
    pub devices: Arc<Mutex<BTreeMap<String, BTreeMap<String, Value>>>>,
    pub device_messages: Arc<Mutex<VecDeque<DeviceMessageRecord>>>,
    pub device_message_txns: Arc<Mutex<BTreeSet<String>>>,
    pub device_keys: Arc<Mutex<BTreeMap<(String, String), Value>>>,
    pub one_time_keys: OneTimeKeyStore,
    pub key_backups: Arc<Mutex<BTreeMap<String, Value>>>,
    pub key_backup_restore_tickets: Arc<Mutex<BTreeMap<String, Value>>>,
    pub key_backup_restore_executor_runs: Arc<Mutex<BTreeMap<String, Value>>>,
    pub blobs: Arc<Mutex<BTreeMap<String, BlobRecord>>>,
    pub push_devices: Arc<Mutex<Vec<Value>>>,
    pub push_rules: Arc<Mutex<BTreeMap<(String, String), PushRuleRecord>>>,
    pub outbound_push_bridge_cache: Arc<Mutex<BTreeMap<String, OutboundPushBridgeCacheRecord>>>,
    pub presence: Arc<Mutex<BTreeMap<String, PresenceRecord>>>,
    pub typing: Arc<Mutex<BTreeMap<(String, String), TypingRecord>>>,
    pub webrtc_sessions: Arc<Mutex<BTreeMap<String, WebrtcSessionRecord>>>,
    pub policy_documents: Arc<Mutex<BTreeMap<String, PolicyDocumentRecord>>>,
    pub moderation_reports: Arc<Mutex<Vec<Value>>>,
    pub moderation_actions: Arc<Mutex<Vec<Value>>>,
    pub audit_log: Arc<Mutex<Vec<Value>>>,
    pub federation_operations: Arc<Mutex<Vec<Operation>>>,
}

#[derive(Clone, Debug)]
pub struct SessionRecord {
    pub token_hash: String,
    pub actor: String,
    pub device_id: String,
    pub audience: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Clone, Debug)]
pub struct DeviceInventoryRecord {
    pub actor: String,
    pub device_id: String,
    pub display_name: Option<String>,
    pub verification_state: String,
    pub payload: Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Clone, Debug)]
pub struct AccountRecord {
    pub did: String,
    pub handle: String,
    pub display_name: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct IdentityDocumentRecord {
    pub did: String,
    pub did_document: Value,
    pub key_log_head: Option<String>,
    pub seq: u64,
    pub method_evidence: Value,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct IdentityLogRecord {
    pub event_hash: String,
    pub did: String,
    pub seq: u64,
    pub operation: Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct ContactRecord {
    pub requester: String,
    pub target: String,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct SpaceInviteRecord {
    pub invite_id: String,
    pub space_id: String,
    pub inviter: String,
    pub invitee: Option<String>,
    pub invite_token: String,
    pub status: String,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct SpaceMetaRecord {
    pub owner: String,
    pub deleted: bool,
    pub discoverability: String,
    pub plaintext_visible_services: BTreeSet<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct SchemaRecord {
    pub schema_id: String,
    pub kind: String,
    pub version: String,
    pub name: Option<String>,
    pub owner: String,
    pub definition: Value,
    pub active: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct MessageRecord {
    pub event_id: String,
    pub space_id: String,
    pub sender: String,
    pub thread_id: String,
    pub content: Value,
    pub encrypted: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct CanonicalEventRecord {
    pub event_id: String,
    pub actor_id: String,
    pub actor_seq: u64,
    pub space_id: Option<String>,
    pub kind: String,
    pub schema_id: String,
    pub canonical_digest: String,
    pub canonical_bytes: Vec<u8>,
    pub envelope: Value,
    pub received_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct ProjectionEventRecord {
    pub event_id: String,
    pub space_id: String,
    pub event_type: String,
    pub input_event_type: String,
    pub canonical_event_type: String,
    pub operation_type: String,
    pub operation_id: Option<String>,
    pub sender: Option<String>,
    pub payload: Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct DeviceMessageRecord {
    pub txn_id: String,
    pub sender: String,
    pub recipient: String,
    pub device_id: String,
    pub position: i64,
    pub content: Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct BlobRecord {
    pub bytes: Vec<u8>,
    pub storage_path: Option<std::path::PathBuf>,
    pub media_type: String,
    pub filename: Option<String>,
    pub space_id: Option<String>,
    pub encryption: Option<Value>,
    pub uploaded_by: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct FederationTransactionRecord {
    pub origin: String,
    pub txn_id: String,
    pub destination: String,
    pub space_id: Option<String>,
    pub content_digest: String,
    pub status: String,
    pub response: Value,
    pub received_at: chrono::DateTime<chrono::Utc>,
    pub processed_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Clone, Debug)]
pub struct PresenceRecord {
    pub actor: String,
    pub status: String,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct TypingRecord {
    pub actor: String,
    pub space_id: String,
    pub scope_id: Option<String>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct PushRuleRecord {
    pub actor: String,
    pub rule_id: String,
    pub enabled: bool,
    pub actions: Vec<String>,
    pub conditions: Value,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct OutboundPushBridgeCacheRecord {
    pub push_gateway_url: String,
    pub service_base_url: String,
    pub bridge_describe_url: String,
    pub fetch_state: String,
    pub cache_state: String,
    pub contract_digest: String,
    pub fetched_at: chrono::DateTime<chrono::Utc>,
    pub remote_contract: Value,
}

#[derive(Clone, Debug)]
pub struct WebrtcSessionRecord {
    pub session_id: String,
    pub space_id: String,
    pub created_by: String,
    pub participants: BTreeSet<String>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub next_seq: u64,
    pub signals: Vec<WebrtcSignalRecord>,
}

#[derive(Clone, Debug)]
pub struct WebrtcSignalRecord {
    pub seq: u64,
    pub sender: String,
    pub message_type: String,
    pub payload: Value,
    pub proofs: Vec<Value>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct PolicyDocumentRecord {
    pub policy_id: String,
    pub owner: String,
    pub scope: String,
    pub subject_ref: String,
    pub policy_type: String,
    pub payload: Value,
    pub active: bool,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl AppState {
    pub fn new(config: AppConfig, db: Db) -> Self {
        let mut spaces = SpaceSearchIndex::new();
        let mut demo = SpaceSearchEntry::new(
            SpaceId::new("cx:space:01js0sp0000000000000000000").expect("valid demo space id"),
            "Contrix Demo Space",
        );
        demo.description = Some("Shared demo Space served by soland".to_owned());
        demo.public = true;
        demo.members
            .insert(Did::new("did:web:alice.example").expect("valid did"));
        demo.tags.insert("demo".to_owned());
        demo.category = Some("collaboration".to_owned());
        spaces.upsert(demo);
        let now = chrono::Utc::now();
        let mut accounts = BTreeMap::new();
        accounts.insert(
            "did:web:alice.example".to_owned(),
            AccountRecord {
                did: "did:web:alice.example".to_owned(),
                handle: "@alice".to_owned(),
                display_name: Some("Alice Example".to_owned()),
                created_at: now,
            },
        );
        let mut space_meta = BTreeMap::new();
        space_meta.insert(
            "cx:space:01js0sp0000000000000000000".to_owned(),
            SpaceMetaRecord {
                owner: "did:web:alice.example".to_owned(),
                deleted: false,
                discoverability: "public".to_owned(),
                plaintext_visible_services: BTreeSet::new(),
                created_at: now,
                updated_at: now,
            },
        );

        let service_did = config.service_did.clone();

        let persistence: Arc<dyn PersistenceStore> = db
            .pool
            .as_ref()
            .map(|pool| {
                Arc::new(PgPersistenceStore::new(pool.clone())) as Arc<dyn PersistenceStore>
            })
            .unwrap_or_else(|| Arc::new(MemoryPersistenceStore::new()));
        if let Err(error) = persistence.accounts().put(
            accounts
                .get("did:web:alice.example")
                .expect("demo account exists"),
        ) {
            tracing::warn!(%error, "failed to seed demo account into persistence store");
        }
        if let Err(error) = persistence.space_meta().put(
            "cx:space:01js0sp0000000000000000000",
            space_meta
                .get("cx:space:01js0sp0000000000000000000")
                .expect("demo space exists"),
        ) {
            tracing::warn!(%error, "failed to seed demo space metadata into persistence store");
        }

        Self {
            config,
            repo: db
                .pool
                .as_ref()
                .map(|pool| Arc::new(PgRepoAdapter::new(pool.clone())) as RepoAdapterRef)
                .unwrap_or_else(|| Arc::new(MemoryRepoAdapter::new())),
            hlc: ServerHlc::new(&service_did),
            projection: Arc::new(Mutex::new(ProjectionState::new())),
            authz: AuthzEngine::new(),
            db,
            persistence,
            spaces: Arc::new(Mutex::new(spaces)),
            space_meta: Arc::new(Mutex::new(space_meta)),
            schemas: Arc::new(Mutex::new(core_schema_records(now, &service_did))),
            accounts: Arc::new(Mutex::new(accounts)),
            identity_documents: Arc::new(Mutex::new(BTreeMap::new())),
            identity_log_events: Arc::new(Mutex::new(BTreeMap::new())),
            did_resolver: {
                let mut resolver = CompositeDidResolver::new();
                resolver.push(DidUuidResolver::new());
                resolver.push(DidWebResolver::new());
                resolver.push(DidKeyResolver::new());
                Arc::new(Mutex::new(resolver))
            },
            contacts: Arc::new(Mutex::new(BTreeMap::new())),
            space_invites: Arc::new(Mutex::new(BTreeMap::new())),
            sessions: Arc::new(Mutex::new(BTreeMap::new())),
            messages: Arc::new(Mutex::new(Vec::new())),
            events: Arc::new(Mutex::new(BTreeMap::new())),
            projection_events: Arc::new(Mutex::new(Vec::new())),
            devices: Arc::new(Mutex::new(BTreeMap::new())),
            device_messages: Arc::new(Mutex::new(VecDeque::new())),
            device_message_txns: Arc::new(Mutex::new(BTreeSet::new())),
            device_keys: Arc::new(Mutex::new(BTreeMap::new())),
            one_time_keys: Arc::new(Mutex::new(BTreeMap::new())),
            key_backups: Arc::new(Mutex::new(BTreeMap::new())),
            key_backup_restore_tickets: Arc::new(Mutex::new(BTreeMap::new())),
            key_backup_restore_executor_runs: Arc::new(Mutex::new(BTreeMap::new())),
            blobs: Arc::new(Mutex::new(BTreeMap::new())),
            push_devices: Arc::new(Mutex::new(Vec::new())),
            push_rules: Arc::new(Mutex::new(BTreeMap::new())),
            outbound_push_bridge_cache: Arc::new(Mutex::new(BTreeMap::new())),
            presence: Arc::new(Mutex::new(BTreeMap::new())),
            typing: Arc::new(Mutex::new(BTreeMap::new())),
            webrtc_sessions: Arc::new(Mutex::new(BTreeMap::new())),
            policy_documents: Arc::new(Mutex::new(BTreeMap::new())),
            moderation_reports: Arc::new(Mutex::new(Vec::new())),
            moderation_actions: Arc::new(Mutex::new(Vec::new())),
            audit_log: Arc::new(Mutex::new(Vec::new())),
            federation_operations: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

fn core_schema_records(
    now: chrono::DateTime<chrono::Utc>,
    service_did: &str,
) -> BTreeMap<String, SchemaRecord> {
    let mut records = artifacts::schema_entries()
        .iter()
        .map(|entry| {
            let kind = schema_kind_from_id(&entry.schema_id);
            (
                entry.schema_id.clone(),
                SchemaRecord {
                    schema_id: entry.schema_id.clone(),
                    kind,
                    version: schema_version_from_id(&entry.schema_id),
                    name: Some(schema_name_from_id(&entry.schema_id)),
                    owner: service_did.to_owned(),
                    definition: json!({
                        "$id": entry.schema_id.clone(),
                        "$schema": "https://json-schema.org/draft/2020-12/schema",
                        "type": "object",
                        "additionalProperties": true,
                        "x-contrix-artifact": {
                            "source": "contrix-spec/artifacts",
                            "file": entry.file.clone()
                        }
                    }),
                    active: true,
                    created_at: now,
                    updated_at: now,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();

    for (schema_id, kind, name) in [
        ("cx.schema.entity.generic.v1", "entity", "Generic entity"),
        ("cx.schema.entity.task.v1", "entity", "Task entity"),
        ("cx.schema.entity.channel.v1", "entity", "Channel entity"),
        ("cx.schema.entity.topic.v1", "entity", "Topic entity"),
        (
            "cx.schema.entity.memory_semantic.v1",
            "entity",
            "Semantic memory entity",
        ),
        (
            "cx.schema.entity.agent_run.v1",
            "entity",
            "Agent run entity",
        ),
        ("cx.schema.event.message.v1", "event", "Message event"),
        ("cx.schema.event.reaction.v1", "event", "Reaction event"),
        ("cx.schema.event.redaction.v1", "event", "Redaction event"),
        (
            "cx.schema.operation.message_create.v1",
            "operation",
            "Message create operation",
        ),
        (
            "cx.schema.operation.message_revise.v1",
            "operation",
            "Message revise operation",
        ),
        (
            "cx.schema.operation.redaction.v1",
            "operation",
            "Redaction operation",
        ),
        (
            "cx.schema.operation.reaction.v1",
            "operation",
            "Reaction operation",
        ),
        (
            "cx.schema.operation.entity_create.v1",
            "operation",
            "Entity create operation",
        ),
        (
            "cx.schema.operation.entity_mutation.v1",
            "operation",
            "Entity mutation operation",
        ),
        (
            "cx.schema.operation.relation_create.v1",
            "operation",
            "Relation create operation",
        ),
        (
            "cx.schema.operation.relation_mutation.v1",
            "operation",
            "Relation mutation operation",
        ),
        (
            "cx.schema.operation.membership.v1",
            "operation",
            "Membership operation",
        ),
        (
            "cx.schema.operation.space_lifecycle.v1",
            "operation",
            "Space lifecycle operation",
        ),
        (
            "cx.schema.operation.read_marker.v1",
            "operation",
            "Read marker operation",
        ),
        ("cx.schema.cursor.v1", "cursor", "Cursor envelope"),
        ("cx.schema.grant.v1", "grant", "Capability grant"),
        (
            "cx.schema.encrypted_envelope.v1",
            "envelope",
            "Encrypted payload envelope",
        ),
    ] {
        records
            .entry(schema_id.to_owned())
            .or_insert_with(|| SchemaRecord {
                schema_id: schema_id.to_owned(),
                kind: kind.to_owned(),
                version: "1".to_owned(),
                name: Some(name.to_owned()),
                owner: service_did.to_owned(),
                definition: json!({
                    "$id": schema_id,
                    "type": "object",
                    "additionalProperties": true,
                    "x-contrix-compatibility": "soland-local-schema-alias"
                }),
                active: true,
                created_at: now,
                updated_at: now,
            });
    }

    records
}

fn schema_kind_from_id(schema_id: &str) -> String {
    schema_id
        .strip_prefix("cx.schema.")
        .and_then(|rest| rest.strip_suffix(".v1").or(Some(rest)))
        .and_then(|rest| rest.split(['.', '_']).next())
        .filter(|kind| !kind.is_empty())
        .unwrap_or("schema")
        .to_owned()
}

fn schema_version_from_id(schema_id: &str) -> String {
    schema_id
        .rsplit_once(".v")
        .map(|(_, version)| version.to_owned())
        .unwrap_or_else(|| "1".to_owned())
}

fn schema_name_from_id(schema_id: &str) -> String {
    schema_id
        .strip_prefix("cx.schema.")
        .unwrap_or(schema_id)
        .replace(['.', '_'], " ")
}
