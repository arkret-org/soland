use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::{Arc, Mutex},
};

use contrix_sdk::{Did, Operation, SpaceId, SpaceSearchEntry, SpaceSearchIndex};
use serde_json::Value;

use crate::db::Db;
use crate::hlc::ServerHlc;
use crate::repo::{MemoryRepoAdapter, PgRepoAdapter, RepoAdapterRef};

type OneTimeKeyStore = Arc<Mutex<BTreeMap<(String, String), Vec<Value>>>>;

#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    pub repo: RepoAdapterRef,
    pub hlc: ServerHlc,
    pub spaces: Arc<Mutex<SpaceSearchIndex>>,
    pub space_meta: Arc<Mutex<BTreeMap<String, SpaceMetaRecord>>>,
    pub accounts: Arc<Mutex<BTreeMap<String, AccountRecord>>>,
    pub contacts: Arc<Mutex<BTreeMap<(String, String), ContactRecord>>>,
    pub sessions: Arc<Mutex<BTreeMap<String, SessionRecord>>>,
    pub messages: Arc<Mutex<Vec<MessageRecord>>>,
    pub projection_events: Arc<Mutex<Vec<ProjectionEventRecord>>>,
    pub devices: Arc<Mutex<BTreeMap<String, BTreeMap<String, Value>>>>,
    pub device_messages: Arc<Mutex<VecDeque<DeviceMessageRecord>>>,
    pub device_message_txns: Arc<Mutex<BTreeSet<String>>>,
    pub device_keys: Arc<Mutex<BTreeMap<(String, String), Value>>>,
    pub one_time_keys: OneTimeKeyStore,
    pub blobs: Arc<Mutex<BTreeMap<String, BlobRecord>>>,
    pub push_devices: Arc<Mutex<Vec<Value>>>,
    pub moderation_reports: Arc<Mutex<Vec<Value>>>,
    pub federation_operations: Arc<Mutex<Vec<Operation>>>,
}

#[derive(Clone, Debug)]
pub struct SessionRecord {
    pub token: String,
    pub actor: String,
    pub device_id: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct AccountRecord {
    pub did: String,
    pub handle: String,
    pub display_name: Option<String>,
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
pub struct SpaceMetaRecord {
    pub owner: String,
    pub deleted: bool,
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
pub struct ProjectionEventRecord {
    pub event_id: String,
    pub space_id: String,
    pub event_type: String,
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
    pub content: Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct BlobRecord {
    pub bytes: Vec<u8>,
    pub media_type: String,
    pub filename: Option<String>,
    pub uploaded_by: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl AppState {
    pub fn new(db: Db) -> Self {
        let mut spaces = SpaceSearchIndex::new();
        let mut demo = SpaceSearchEntry::new(
            SpaceId::new("cx:space:01js0sp0000000000000000000").expect("valid demo space id"),
            "Contrix Demo Space",
        );
        demo.description = Some("Shared demo Space served by serverx".to_owned());
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
                created_at: now,
                updated_at: now,
            },
        );

        Self {
            repo: db
                .pool
                .as_ref()
                .map(|pool| Arc::new(PgRepoAdapter::new(pool.clone())) as RepoAdapterRef)
                .unwrap_or_else(|| Arc::new(MemoryRepoAdapter::new())),
            hlc: ServerHlc::new("did:web:serverx.local"),
            db,
            spaces: Arc::new(Mutex::new(spaces)),
            space_meta: Arc::new(Mutex::new(space_meta)),
            accounts: Arc::new(Mutex::new(accounts)),
            contacts: Arc::new(Mutex::new(BTreeMap::new())),
            sessions: Arc::new(Mutex::new(BTreeMap::new())),
            messages: Arc::new(Mutex::new(Vec::new())),
            projection_events: Arc::new(Mutex::new(Vec::new())),
            devices: Arc::new(Mutex::new(BTreeMap::new())),
            device_messages: Arc::new(Mutex::new(VecDeque::new())),
            device_message_txns: Arc::new(Mutex::new(BTreeSet::new())),
            device_keys: Arc::new(Mutex::new(BTreeMap::new())),
            one_time_keys: Arc::new(Mutex::new(BTreeMap::new())),
            blobs: Arc::new(Mutex::new(BTreeMap::new())),
            push_devices: Arc::new(Mutex::new(Vec::new())),
            moderation_reports: Arc::new(Mutex::new(Vec::new())),
            federation_operations: Arc::new(Mutex::new(Vec::new())),
        }
    }
}
