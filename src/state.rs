use arc_swap::ArcSwap;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::broadcast;

use contrix_sdk::{
    Did, SpaceId, SpaceSearchEntry, SpaceSearchIndex, identity::CompositeDidResolver,
};
use serde_json::{Value, json};

use crate::artifacts;
use crate::authz::AuthzEngine;
use crate::config::{AnchorerSigningKeyOrigin, AppConfig};
use crate::db::Db;
use crate::hlc::ServerHlc;
use crate::object_storage::{ObjectStorage, build_object_storage};
use crate::persistence::{MemoryPersistenceStore, PersistenceStore, PgPersistenceStore};
use crate::reducer::ProjectionState;

// `did_resolver_chain.rs` lives at `src/did_resolver_chain.rs`; declare it as
// a submodule of `state` so `AppState::new` can construct the resolver chain
// locally and re-export it as `crate::state::did_resolver_chain`.
#[path = "did_resolver_chain.rs"]
pub mod did_resolver_chain;

/// broadcast payload for the
/// [`AppState::event_broadcast`] channel. Subscribers filter by
/// `space_id` first, then dispatch on `kind` to produce the right
/// NDJSON frame.
///
/// added control-frame variants alongside the original `Event`
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
    ResyncRequired { reason: String },
    /// Session token invalidated mid-stream — client MUST close.
    Unauthorized { reason: String },
}

impl EventNotification {
    pub fn event(space_id: String, cursor: String, event_payload: Value) -> Self {
        Self {
            space_id,
            kind: EventNotificationKind::Event {
                cursor,
                event_payload,
            },
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
            kind: EventNotificationKind::Frontier {
                state_root,
                anchor_id,
            },
        }
    }
}

/// Single-process service state. Every long-lived data surface lives behind
/// `persistence` (a `dyn PersistenceStore`); the few remaining fields are
/// either non-record state (config, db pool, hlc, authz engine) or runtime
/// facets that don't fit the trait shape (in-memory `SpaceSearchIndex`,
/// `CompositeDidResolver`, `ProjectionState`).
///
#[derive(Clone)]
pub struct AppState {
    pub config: AppConfig,
    pub db: Db,
    pub persistence: Arc<dyn PersistenceStore>,
    pub object_storage: Arc<dyn ObjectStorage>,
    pub hlc: ServerHlc,
    pub projection: Arc<Mutex<ProjectionState>>,
    pub authz: AuthzEngine,
    pub spaces: Arc<Mutex<SpaceSearchIndex>>,
    pub did_resolver: Arc<Mutex<CompositeDidResolver>>,
    /// Move/Anchor/Lattice runtime stores.
    /// In-memory backends from the SDK; production deployments will
    /// swap these for Pg-backed implementations behind the same trait
    /// surface (`MoveStore` / `AnchorStore` / `CellStore` / `CellRegistry`).
    pub move_store: Arc<contrix_sdk::state_res::MemoryMoveStore>,
    pub anchor_store: Arc<contrix_sdk::state_res::MemoryAnchorStore>,
    pub cell_store: Arc<contrix_sdk::state_res::MemoryCellStore>,
    pub cell_registry: Arc<contrix_sdk::state_res::MemoryCellRegistry>,
    /// Live event notification channel for `cx.events.subscribe`
    /// long-poll/SSE streaming. Writers
    /// (`routing::events::projection::project_accepted_operations`,
    /// `routing::federation::move_anchor::submit_anchor`,
    /// `crate::anchorer::AnchorerWorker`) broadcast each accepted
    /// projection event; subscribers in `routing::events::sync::events_subscribe`
    /// `recv()` on a fresh receiver and write live frames to the NDJSON
    /// streaming response. Capacity 1024 — enough for a multi-Space
    /// principal under burst load; receivers that fall behind get
    /// `RecvError::Lagged` and emit a `dropped` control frame to nudge
    /// the client to resync.
    pub event_broadcast: broadcast::Sender<EventNotification>,
    /// Persistent Ed25519 signing key for AnchorerWorker +
    /// admin endpoints (`admin_reconfigure_anchorer`, `admin_repair_bottom`).
    /// Loaded from `AppConfig::anchorer_signing_key_seed` at boot when set;
    /// otherwise minted from `sha256(service_did || nanos_since_epoch)` and
    /// flagged as `AnchorerSigningKeyOrigin::Ephemeral` so a sticky-warn
    /// fires on first use.
    ///
    /// Shared across all signing paths so the AnchorerWorker, the
    /// `service_admin_signer` admin shortcut, and the threshold partial-
    /// signature coordinator all bind to the **same** key/DID identity.
    /// Swapped lock-free via [`ArcSwap`] so
    /// the `POST /api/admin/v1/spaces/{id}/anchorer/rotate-signing-key`
    /// endpoint can publish a fresh ed25519 seed without tearing concurrent
    /// signing passes. Readers acquire the current key via `load_full()`
    /// (returns `Arc<SigningKey>`); writers `store(...)` a new `Arc`.
    pub anchorer_signing_key: Arc<ArcSwap<SigningKey>>,
    /// The origin tag rotates with the key. Stored alongside it
    /// behind a [`Mutex`] (one-shot writes from the rotation path are not
    /// in the hot read path; the per-pass diagnostic helper just snapshots).
    pub anchorer_signing_key_origin: Arc<Mutex<AnchorerSigningKeyOrigin>>,
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
    /// Canonical Contrix event kind (e.g. `cx.message.create`).
    pub event_kind: String,
    pub operation_type: String,
    pub operation_id: Option<String>,
    pub sender: Option<String>,
    pub payload: Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct DeviceMessageRecord {
    pub idempotency_key: String,
    pub sender: String,
    pub recipient: String,
    pub device_id: String,
    pub position: i64,
    pub content: Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct BlobRecord {
    pub sha256: String,
    pub size_bytes: i64,
    pub storage_backend: String,
    pub storage_key: String,
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
    /// Explicit trust state for the cached snapshot. This introduces
    /// `pending` / `trusted` / `revoked` so `verify_contract_freshness` can
    /// fail-closed when a snapshot has not yet been promoted to trusted.
    pub trust_level: String,
    /// Last time we affirmatively re-checked the upstream contract; bumped
    /// independently from `fetched_at` so freshness/age policy can reject
    /// snapshots that haven't been re-verified within `max_age`.
    pub freshness_at: chrono::DateTime<chrono::Utc>,
    /// Opaque server-issued ETag from the upstream describe response.
    /// Compared alongside `contract_digest` so a same-digest-but-rotated
    /// etag still trips drift fail-closed.
    pub etag: String,
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

/// One row of the persistent multisig coordinator buffer.
///
/// Holds an in-flight pending Anchor that is awaiting threshold partial
/// signatures. The `partials` map is keyed by signer DID → submitted partial
/// payload (`{signature_b64, kid, submitted_at}`). When the number of
/// partials reaches `threshold_k`, the leader aggregates them via SDK
/// `ThresholdAggregator` and publishes the final threshold-signed Anchor,
/// then deletes the row.
#[derive(Clone, Debug)]
pub struct MultisigPendingRecord {
    pub anchor_id: String,
    pub space_id: String,
    pub threshold_k: u32,
    pub threshold_n: u32,
    pub members: Vec<String>,
    /// Canonical bytes (base64) the partial signatures sign over. Empty when
    /// the buffer was created without an explicit canonical body (smoke
    /// tests). Real partial-signature aggregation requires this to be
    /// non-empty.
    pub canonical_b64: String,
    /// `signer_did` -> JSON `{signature_b64, kid, submitted_at}`.
    pub partials: BTreeMap<String, Value>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// Node id of the watchdog instance currently leasing this row, or
    /// `None` when unclaimed. The lease is valid until
    /// [`MultisigPendingRecord::claimed_until`].
    pub claimed_by_node_id: Option<String>,
    /// Lease expiry timestamp. A row is "claimable" when this is `None` or
    /// in the past.
    pub claimed_until: Option<chrono::DateTime<chrono::Utc>>,
    /// Partition-tolerant fencing token. Every successful
    /// `try_claim` bumps this counter; a stale leader (whose lease was
    /// silently superseded after a network partition healed) carries the
    /// pre-bump value so its post-aggregate `delete_with_fence` /
    /// `renew_claim` is rejected at the row level. Monotonic across the
    /// row's lifetime.
    pub claim_seq: i64,
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
    /// Snapshot the persistent Ed25519 signing key shared by
    /// the AnchorerWorker and all admin signing paths. Returns a fresh
    /// `Arc<SigningKey>` (lock-free `ArcSwap::load_full`) so callers can
    /// hold the snapshot for the duration of a signing pass even if the
    /// rotate-signing-key endpoint races with them.
    pub fn anchorer_signing_key(&self) -> Arc<SigningKey> {
        self.anchorer_signing_key.load_full()
    }

    /// Origin tag for diagnostics (`Configured` / `Ephemeral` / `Rotated`).
    pub fn anchorer_signing_key_origin(&self) -> AnchorerSigningKeyOrigin {
        *self
            .anchorer_signing_key_origin
            .lock()
            .expect("anchorer signing key origin lock")
    }

    /// Hot-rotate the AnchorerWorker signing key. Writers swap
    /// the `ArcSwap` and update the origin tag in lockstep. Returns the
    /// newly-published `Arc<SigningKey>` for callers (the rotate-signing-key
    /// endpoint uses it to compute the resulting did:key kid).
    pub fn rotate_anchorer_signing_key(
        &self,
        seed: &[u8; 32],
        origin: AnchorerSigningKeyOrigin,
    ) -> Arc<SigningKey> {
        let new_key = Arc::new(SigningKey::from_bytes(seed));
        self.anchorer_signing_key.store(new_key.clone());
        if let Ok(mut guard) = self.anchorer_signing_key_origin.lock() {
            *guard = origin;
        }
        new_key
    }

    pub fn new(config: AppConfig, db: Db) -> Self {
        let mut spaces = SpaceSearchIndex::new();
        let mut demo = SpaceSearchEntry::new(
            SpaceId::new("cx:space:0196419b-0000-7000-8000-000000000000")
                .expect("valid demo space id"),
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

        let object_storage = build_object_storage(&config.object_storage)
            .expect("object storage backend initializes");

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
        if let Err(error) = persistence.space_meta().put(
            "cx:space:0196419b-0000-7000-8000-000000000000",
            &demo_space_meta,
        ) {
            tracing::warn!(%error, "failed to seed demo space metadata into persistence store");
        }

        for record in core_schema_records(now, &service_did).into_values() {
            if let Err(error) = persistence.schemas().put(record) {
                tracing::warn!(%error, "failed to seed core schema into persistence store");
            }
        }

        // Build the production DID resolver chain before the struct literal
        // so we can still
        // borrow `&config` for the helper before `config` itself is
        // moved into `Self.config`.
        let did_resolver = Arc::new(Mutex::new(
            self::did_resolver_chain::build_did_resolver_chain(&config),
        ));

        // Derive the AnchorerWorker's Ed25519 signing key.
        // Resolution order:
        //   1. KeyStore (when `use_keystore=true` and the platform store
        //      has a previously-persisted seed under our id) → Configured.
        //   2. `config.anchorer_signing_key_seed` (env-loaded) → Configured.
        //      When `use_keystore=true` we *also* persist this seed back
        //      to the KeyStore on first boot so subsequent restarts skip
        //      the env path.
        //   3. SHA-256(service_did || boot_nanos) → Ephemeral.
        let (signing_seed, anchorer_signing_key_origin) =
            (|| -> ([u8; 32], AnchorerSigningKeyOrigin) {
                if config.use_keystore {
                    let app_id = format!("soland.{service_did}");
                    let key_id = format!("contrix:signer:soland-anchorer:{service_did}");
                    let store = contrix_sdk::keystore::platform_default_keystore(&app_id);
                    if let Ok(bytes) = store.load(&key_id) {
                        if bytes.len() == 32 {
                            let mut seed = [0u8; 32];
                            seed.copy_from_slice(&bytes);
                            tracing::info!(%key_id, "loaded anchorer signing seed from platform KeyStore");
                            return (seed, AnchorerSigningKeyOrigin::Configured);
                        }
                        tracing::warn!(%key_id, len = bytes.len(),
                        "platform KeyStore returned non-32-byte payload; falling back");
                    }
                    if let Some(seed) = config.anchorer_signing_key_seed {
                        if let Err(error) = store.store(&key_id, &seed) {
                            tracing::warn!(%error, %key_id,
                            "failed to seed platform KeyStore from env-supplied seed");
                        } else {
                            tracing::info!(%key_id,
                            "persisted env-supplied anchorer seed into platform KeyStore");
                        }
                        return (seed, AnchorerSigningKeyOrigin::Configured);
                    }
                    // Mint + persist a one-shot seed.
                    let mut seed = [0u8; 32];
                    getrandom_seed(&mut seed);
                    if let Err(error) = store.store(&key_id, &seed) {
                        tracing::warn!(%error, %key_id,
                        "failed to persist freshly-minted anchorer seed to KeyStore");
                    } else {
                        tracing::info!(%key_id,
                        "minted + persisted fresh anchorer seed via platform KeyStore");
                    }
                    return (seed, AnchorerSigningKeyOrigin::Configured);
                }
                if let Some(seed) = config.anchorer_signing_key_seed {
                    return (seed, AnchorerSigningKeyOrigin::Configured);
                }
                let mut hasher = Sha256::new();
                hasher.update(b"soland:anchorer-ephemeral:");
                hasher.update(service_did.as_bytes());
                let boot_nanos = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_nanos() as u64)
                    .unwrap_or(0);
                hasher.update(boot_nanos.to_le_bytes());
                let seed: [u8; 32] = hasher.finalize().into();
                (seed, AnchorerSigningKeyOrigin::Ephemeral)
            })();

        let anchorer_signing_key =
            Arc::new(ArcSwap::from_pointee(SigningKey::from_bytes(&signing_seed)));
        let anchorer_signing_key_origin = Arc::new(Mutex::new(anchorer_signing_key_origin));

        Self {
            config,
            hlc: ServerHlc::new(&service_did),
            projection: Arc::new(Mutex::new(ProjectionState::new())),
            authz: AuthzEngine::new(),
            db,
            persistence,
            object_storage,
            spaces: Arc::new(Mutex::new(spaces)),
            did_resolver,
            move_store: Arc::new(contrix_sdk::state_res::MemoryMoveStore::default()),
            anchor_store: Arc::new(contrix_sdk::state_res::MemoryAnchorStore::default()),
            cell_store: Arc::new(contrix_sdk::state_res::MemoryCellStore::default()),
            // Register all soland LatticeKind impls into the SDK cell
            // registry so the
            // Move/Anchor receive pipeline resolves every spec-declared
            // cell family. Replaces the SDK's built-in defaults (which
            // covered only ~10 generic families).
            cell_registry: Arc::new(crate::reducer::lattice_kinds::build_sdk_cell_registry()),
            // Live event broadcast for cx.events.subscribe streaming.
            // Capacity 1024 events; readers
            // falling behind get `Lagged` and emit `dropped` control frames.
            event_broadcast: broadcast::channel::<EventNotification>(1024).0,
            anchorer_signing_key,
            anchorer_signing_key_origin,
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
        ("cx.schema.space.v1", "space", "Space object"),
        ("cx.schema.flow.v1", "flow", "Flow object"),
        ("cx.schema.place.v1", "place", "Place object"),
        ("cx.schema.morph.v1", "morph", "Morph object"),
        ("cx.schema.relation.v1", "relation", "Relation object"),
        ("cx.schema.view.v1", "view", "View object"),
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
            "cx.schema.operation.container_move_item.v1",
            "operation",
            "Container move item operation",
        ),
        (
            "cx.schema.operation.container_rebalance.v1",
            "operation",
            "Container rebalance operation",
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
                    "additionalProperties": true
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

/// Fill `out` with cryptographically secure random bytes via
/// `rand::OsRng`. Used by both the boot path (one-shot KeyStore mint) and
/// the rotate-signing-key endpoint.
pub(crate) fn getrandom_seed(out: &mut [u8; 32]) {
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(out);
}
