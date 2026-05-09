use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use tokio::sync::broadcast;

use contrix_sdk::{
    Did, SpaceId, SpaceSearchEntry, SpaceSearchIndex,
    identity::CompositeDidResolver,
};
use serde_json::{Value, json};

use crate::artifacts;
use crate::authz::AuthzEngine;
use crate::config::{AnchorerSigningKeyOrigin, AppConfig};
use crate::db::Db;
use crate::hlc::ServerHlc;
use crate::persistence::{MemoryPersistenceStore, PersistenceStore, PgPersistenceStore};
use crate::reducer::ProjectionState;
use crate::repo::{MemoryRepoAdapter, PgRepoAdapter, RepoAdapterRef};

// C10.B (2026-05-09 十八轮 并行) — `did_resolver_chain.rs` lives at
// `src/did_resolver_chain.rs`; declared here as a submodule of `state`
// (rather than top-level via `lib.rs`) because the parallel task A in
// this branch holds the `lib.rs` edit lock. Re-exported as
// `crate::state::did_resolver_chain` and used immediately below in
// `AppState::new`.
#[path = "did_resolver_chain.rs"]
pub mod did_resolver_chain;

/// C10.B (2026-05-09 十轮 / 十五轮): broadcast payload for the
/// [`AppState::event_broadcast`] channel. Subscribers filter by
/// `space_id` first, then dispatch on `kind` to produce the right
/// NDJSON frame.
///
/// 十五轮 added control-frame variants alongside the original `Event`
/// (mid-stream control frames per spec):
///   - `EpochRotation` — emitted when `cx.component.mls.epoch.v1` cell
///     changes (E2EE epoch shift; clients MUST re-fetch keys)
///   - `Frontier` — anchor frontier advanced (Snapshot of cursor /
///     state_root after `apply_anchor`); clients use this as a
///     resync waypoint
///   - `ResyncRequired` — server detected per-subscriber drift; client
///     MUST drop local cache and re-subscribe with `from=null`
///   - `Unauthorized` — subscriber's session token revoked / expired
///     mid-stream; client MUST close + re-auth
#[derive(Clone, Debug)]
pub struct EventNotification {
    pub space_id: String,
    pub kind: EventNotificationKind,
}

#[derive(Clone, Debug)]
pub enum EventNotificationKind {
    /// Ordinary projection event (one `cx.message.create` etc.).
    Event {
        /// Stable cursor for the event — typically the canonical
        /// `event_id`. Clients use as resume position.
        cursor: String,
        /// Projection-event JSON (same shape as `projection_event_json`).
        event_payload: Value,
    },
    /// MLS epoch shift detected on `cx.component.mls.epoch.v1` cell.
    EpochRotation {
        /// Old epoch value (the previous CellState::Value if known).
        previous_epoch: Option<Value>,
        /// New epoch value (current CellState::Value after the
        /// triggering apply_anchor).
        new_epoch: Value,
    },
    /// Anchor frontier advanced. Emitted post-`apply_anchor` so clients
    /// can update their resume cursor without waiting for the next event.
    Frontier {
        /// `apply_anchor`'s `post_state_root` (canonical Merkle).
        state_root: String,
        /// The Anchor's id, useful for clients tracking Anchor DAG.
        anchor_id: String,
    },
    /// Per-subscriber drift / corrupted-cursor signal. Clients SHOULD
    /// drop local cache + restart subscription with no `from`.
    ResyncRequired {
        reason: String,
    },
    /// Session token invalidated mid-stream — client MUST close.
    Unauthorized {
        reason: String,
    },
}

impl EventNotification {
    pub fn event(space_id: String, cursor: String, event_payload: Value) -> Self {
        Self {
            space_id,
            kind: EventNotificationKind::Event { cursor, event_payload },
        }
    }

    pub fn epoch_rotation(
        space_id: String,
        previous_epoch: Option<Value>,
        new_epoch: Value,
    ) -> Self {
        Self {
            space_id,
            kind: EventNotificationKind::EpochRotation {
                previous_epoch,
                new_epoch,
            },
        }
    }

    pub fn frontier(space_id: String, anchor_id: String, state_root: String) -> Self {
        Self {
            space_id,
            kind: EventNotificationKind::Frontier { state_root, anchor_id },
        }
    }
}

/// Single-process service state. Every long-lived data surface lives behind
/// `persistence` (a `dyn PersistenceStore`); the few remaining fields are
/// either non-record state (config, db pool, hlc, authz engine), runtime
/// facets that don't fit the trait shape (in-memory `SpaceSearchIndex`,
/// `CompositeDidResolver`, `ProjectionState`), or the temporarily-retained
/// key-backup-restore scaffold maps (T0-2c — `routing/key_backup_restore.rs`
/// uses `BTreeMap` semantics like `iter / retain / get_mut` against these
/// maps, and the trait migration is tracked separately).
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
    pub did_resolver: Arc<Mutex<CompositeDidResolver>>,
    /// Move/Anchor/Lattice runtime stores (C10.B MAL-2..MAL-5).
    /// In-memory backends from the SDK; production deployments will
    /// swap these for Pg-backed implementations behind the same trait
    /// surface (`MoveStore` / `AnchorStore` / `CellStore` / `CellRegistry`).
    pub move_store: Arc<contrix_sdk::state_res::MemoryMoveStore>,
    pub anchor_store: Arc<contrix_sdk::state_res::MemoryAnchorStore>,
    pub cell_store: Arc<contrix_sdk::state_res::MemoryCellStore>,
    pub cell_registry: Arc<contrix_sdk::state_res::MemoryCellRegistry>,
    /// C10.B (2026-05-09 十轮): live event notification channel for
    /// `cx.events.subscribe` long-poll/SSE streaming. Writers
    /// (`routing::projection::project_accepted_operations`,
    /// `routing::move_anchor::submit_anchor`,
    /// `crate::anchorer::AnchorerWorker`) broadcast each accepted
    /// projection event; subscribers in `routing::sync::events_subscribe`
    /// `recv()` on a fresh receiver and write live frames to the NDJSON
    /// streaming response. Capacity 1024 — enough for a multi-Space
    /// principal under burst load; receivers that fall behind get
    /// `RecvError::Lagged` and emit a `dropped` control frame to nudge
    /// the client to resync.
    pub event_broadcast: broadcast::Sender<EventNotification>,
    /// Round 22: persistent Ed25519 signing key for AnchorerWorker +
    /// admin endpoints (`admin_reconfigure_anchorer`, `admin_repair_bottom`).
    /// Loaded from `AppConfig::anchorer_signing_key_seed` at boot when set;
    /// otherwise minted from `sha256(service_did || nanos_since_epoch)` and
    /// flagged as `AnchorerSigningKeyOrigin::Ephemeral` so a sticky-warn
    /// fires on first use.
    ///
    /// Shared across all signing paths so the AnchorerWorker, the
    /// `service_admin_signer` admin shortcut, and the threshold partial-
    /// signature coordinator all bind to the **same** key/DID identity.
    pub anchorer_signing_key: Arc<SigningKey>,
    pub anchorer_signing_key_origin: AnchorerSigningKeyOrigin,
    // T0-2c follow-up: migrate the four key-backup scaffold maps below into
    // `state.persistence.key_backups()` once the routing layer's iter/retain/
    // get_mut patterns are rewritten in terms of the trait.
    pub key_backups: Arc<Mutex<BTreeMap<String, Value>>>,
    pub key_backup_restore_tickets: Arc<Mutex<BTreeMap<String, Value>>>,
    pub key_backup_restore_executor_runs: Arc<Mutex<BTreeMap<String, Value>>>,
    pub key_backup_restore_approval_runs: Arc<Mutex<BTreeMap<String, Value>>>,
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
    /// Canonical Contrix event kind (e.g. `cx.message.create`). Spec
    /// M-01 collapsed the legacy `event_type / input_event_type /
    /// canonical_event_type` triple into this single field.
    pub event_kind: String,
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
    /// Round 22: Borrow the persistent Ed25519 signing key shared by the
    /// AnchorerWorker and all admin signing paths.
    pub fn anchorer_signing_key(&self) -> &SigningKey {
        &self.anchorer_signing_key
    }

    /// Round 22: Origin tag for diagnostics (Configured / Ephemeral).
    pub fn anchorer_signing_key_origin(&self) -> AnchorerSigningKeyOrigin {
        self.anchorer_signing_key_origin
    }

    pub fn new(config: AppConfig, db: Db) -> Self {
        let mut spaces = SpaceSearchIndex::new();
        let mut demo = SpaceSearchEntry::new(
            SpaceId::new("cx:space:0196419b-0000-7000-8000-000000000000").expect("valid demo space id"),
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

        let service_did = config.service_did.clone();

        let persistence: Arc<dyn PersistenceStore> = db
            .pool
            .as_ref()
            .map(|pool| {
                Arc::new(PgPersistenceStore::new(pool.clone())) as Arc<dyn PersistenceStore>
            })
            .unwrap_or_else(|| Arc::new(MemoryPersistenceStore::new()));

        let demo_account = AccountRecord {
            did: "did:web:alice.example".to_owned(),
            handle: "@alice".to_owned(),
            display_name: Some("Alice Example".to_owned()),
            created_at: now,
        };
        if let Err(error) = persistence.accounts().put(&demo_account) {
            tracing::warn!(%error, "failed to seed demo account into persistence store");
        }

        let demo_space_meta = SpaceMetaRecord {
            owner: "did:web:alice.example".to_owned(),
            deleted: false,
            discoverability: "public".to_owned(),
            plaintext_visible_services: BTreeSet::new(),
            created_at: now,
            updated_at: now,
        };
        if let Err(error) = persistence
            .space_meta()
            .put("cx:space:0196419b-0000-7000-8000-000000000000", &demo_space_meta)
        {
            tracing::warn!(%error, "failed to seed demo space metadata into persistence store");
        }

        for record in core_schema_records(now, &service_did).into_values() {
            if let Err(error) = persistence.schemas().put(record) {
                tracing::warn!(%error, "failed to seed core schema into persistence store");
            }
        }

        // C10.B (2026-05-09 十八轮 并行) — build the production DID
        // resolver chain BEFORE the struct literal so we can still
        // borrow `&config` for the helper before `config` itself is
        // moved into `Self.config`.
        let did_resolver = Arc::new(Mutex::new(
            self::did_resolver_chain::build_did_resolver_chain(&config),
        ));

        // Round 22 — derive the AnchorerWorker's Ed25519 signing key.
        // Configured: deterministic from the env-supplied seed; Ephemeral:
        // bound to (service_did, boot_nanos) so it's stable for this
        // process lifetime but explicitly NOT persistent.
        let (anchorer_signing_key, anchorer_signing_key_origin) =
            match config.anchorer_signing_key_seed {
                Some(seed) => (
                    Arc::new(SigningKey::from_bytes(&seed)),
                    AnchorerSigningKeyOrigin::Configured,
                ),
                None => {
                    let mut hasher = Sha256::new();
                    hasher.update(b"soland:anchorer-ephemeral:");
                    hasher.update(service_did.as_bytes());
                    let boot_nanos = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_nanos() as u64)
                        .unwrap_or(0);
                    hasher.update(boot_nanos.to_le_bytes());
                    let seed: [u8; 32] = hasher.finalize().into();
                    (
                        Arc::new(SigningKey::from_bytes(&seed)),
                        AnchorerSigningKeyOrigin::Ephemeral,
                    )
                }
            };

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
            did_resolver,
            move_store: Arc::new(contrix_sdk::state_res::MemoryMoveStore::default()),
            anchor_store: Arc::new(contrix_sdk::state_res::MemoryAnchorStore::default()),
            cell_store: Arc::new(contrix_sdk::state_res::MemoryCellStore::default()),
            // C10.B (2026-05-09 五轮 激进模式): bulk-register all 35
            // soland LatticeKind impls into the SDK cell registry so the
            // Move/Anchor receive pipeline resolves every spec-declared
            // cell family. Replaces the SDK's built-in defaults (which
            // covered only ~10 generic families).
            cell_registry: Arc::new(crate::reducer::lattice_kinds::build_sdk_cell_registry()),
            // C10.B (2026-05-09 十轮): live event broadcast for
            // cx.events.subscribe streaming. Capacity 1024 events; readers
            // falling behind get `Lagged` and emit `dropped` control frames.
            event_broadcast: broadcast::channel::<EventNotification>(1024).0,
            anchorer_signing_key,
            anchorer_signing_key_origin,
            key_backups: Arc::new(Mutex::new(BTreeMap::new())),
            key_backup_restore_tickets: Arc::new(Mutex::new(BTreeMap::new())),
            key_backup_restore_executor_runs: Arc::new(Mutex::new(BTreeMap::new())),
            key_backup_restore_approval_runs: Arc::new(Mutex::new(BTreeMap::new())),
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
                            "source": "contrix-spec/spec/v1/artifacts",
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
