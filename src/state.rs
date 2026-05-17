use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use contrix_sdk::identity::CompositeDidResolver;
use contrix_sdk::{Did, SpaceId, SpaceSearchEntry, SpaceSearchIndex};
use ed25519_dalek::SigningKey;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::sync::broadcast;

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
///   - `EpochRotation` — emitted when `cx.component.mls.epoch.v1` cell changes (E2EE epoch shift;
///     clients MUST re-fetch keys)
///   - `Frontier` — anchor frontier advanced (Snapshot of cursor / state_root after
///     `apply_anchor`); clients use this as a resync waypoint
///   - `ResyncRequired` — server detected per-subscriber drift; client MUST drop local cache and
///     re-subscribe with `from=null`
///   - `Unauthorized` — subscriber's session token revoked / expired mid-stream; client MUST close
///     + re-auth
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
    /// In-memory handle release ledger. Records `released_handle → released_at`
    /// for every handle vacated by `claim_handle` / `transfer_handle`; new
    /// claims for a handle still inside `HANDLE_GRACE_PERIOD_SECONDS` are
    /// rejected with `handle_in_grace_period`. Spec: identity-handles.md
    /// (handle release cooldown). The map is server-process-local; persistent
    /// storage lands when the handle CRDT projection ships.
    pub handle_releases: Arc<Mutex<BTreeMap<String, chrono::DateTime<chrono::Utc>>>>,
    /// Erased actors — DID set. Once an actor `erase`s itself, every
    /// subsequent authenticated request from that bearer returns 401
    /// `account_erased` (and directory hits skip the row). Same in-memory
    /// trade-off as `handle_releases`: persistent ledger lands with the
    /// account-state projection.
    pub erased_actors: Arc<Mutex<BTreeSet<String>>>,
    /// Per-actor notifications read marker. `mark_all_read(actor)` writes
    /// `Utc::now()`; the notifications read-side filter uses it to flag
    /// rows as read. Same in-memory shape as the other two.
    pub notification_read_markers: Arc<Mutex<BTreeMap<String, chrono::DateTime<chrono::Utc>>>>,
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
    /// Per-admin signing keys: SDK
    /// [`contrix_sdk::AdminKeyStore`] keyed by the `application_id`
    /// `soland.<service_did>`. Each admin DID in
    /// `config.admin_principal_dids` gets its own ed25519 signing seed
    /// (provisioned at boot in `development_mode`; lazily loaded from the
    /// platform keystore otherwise). The signer for an admin DID is
    /// built via `admin_signer_for(state, admin_did)` — this replaces the
    /// service-wide `service_admin_signer` shortcut for endpoints that
    /// want operator attribution in the audit chain.
    pub admin_keystore: Arc<contrix_sdk::AdminKeyStore>,
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
    /// Free-form short description for directory rendering. Updated via
    /// `POST /api/v1/account/profile` (operationId `cx.account.update_profile`);
    /// rendered by `demo_actors` in directory search results.
    pub bio: Option<String>,
    /// HTTPS URL pointing at the actor's avatar image. Server holds the
    /// link verbatim — no transcoding or caching.
    pub avatar_url: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct WebvhDocumentRecord {
    pub did: String,
    pub did_document: Value,
    pub key_log_head: Option<String>,
    pub seq: u64,
    pub method_evidence: Value,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug)]
pub struct WebvhLogRecord {
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

/// Actor-private account data row (`cx.account_data.set` storage).
///
/// One row per `(actor, data_type)`. `data_type` is the canonical wire key
/// (e.g. `cx.read_receipt.preferences`, `cx.contacts.actor.did:web:alice.example`,
/// `cx.contacts.space.cx:space:0196419b-0000-7000-8000-000000000000`). Soland
/// treats the `payload` as an opaque encrypted blob — no schema validation
/// happens server-side; clients are responsible for canonical encoding.
///
/// Spec: `discovery/client-preferences.md` §2 (storage model) and §3.7
/// (Space remarks, `cx.contacts.space.<space_id>`).
#[derive(Clone, Debug)]
pub struct AccountDataRecord {
    pub actor: String,
    pub data_type: String,
    pub payload: Value,
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
    /// One of `shared` / `joined` / `invited` / `world_readable`. Owner can
    /// flip this via `PUT /api/v1/spaces/{id}/policy`; `world_readable` opens
    /// the event-stream read endpoints to non-members and anonymous callers
    /// (space-and-place.md §3.4 + §3.7).
    pub history_visibility: String,
    /// Optional encryption profile (`mls_rfc9420` / `plaintext`). Cross-checked
    /// against `history_visibility` at create time — `mls_rfc9420` is
    /// incompatible with `world_readable` (space-and-place.md §3.1.3).
    pub encryption_profile: Option<String>,
    pub plaintext_visible_services: BTreeSet<String>,
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

        // Seed deterministic demo data only when explicitly opted in (tests via
        // `test_config()`, dev harnesses via `SOLAND_SEED_DEMO_DATA=true`). In
        // production this stays off so soland deployments don't all advertise
        // the same hard-coded "Contrix Demo Space" id across federation peers.
        if config.seed_demo_data {
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

            let demo_account = AccountRecord {
                did: "did:web:alice.example".to_owned(),
                handle: "@alice".to_owned(),
                display_name: Some("Alice Example".to_owned()),
                bio: None,
                avatar_url: None,
                created_at: now,
            };
            if let Err(error) = persistence.accounts().put(&demo_account) {
                tracing::warn!(%error, "failed to seed demo account into persistence store");
            }

            let demo_space_meta = SpaceMetaRecord {
                owner: "did:web:alice.example".to_owned(),
                deleted: false,
                discoverability: "public".to_owned(),
                history_visibility: "shared".to_owned(),
                encryption_profile: None,
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
        }

        // Build the production DID resolver chain before the struct literal
        // so we can still
        // borrow `&config` for the helper before `config` itself is
        // moved into `Self.config`.
        let did_resolver = Arc::new(Mutex::new(
            self::did_resolver_chain::build_did_resolver_chain_with_identity(
                &config,
                Some(persistence.clone()),
            ),
        ));

        // Derive the AnchorerWorker's Ed25519 signing key.
        // Resolution order:
        //   1. KeyStore (when `use_keystore=true` and the platform store has a previously-persisted
        //      seed under our id) → Configured.
        //   2. `config.anchorer_signing_key_seed` (env-loaded) → Configured. When
        //      `use_keystore=true` we *also* persist this seed back to the KeyStore on first boot
        //      so subsequent restarts skip the env path.
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

        // Per-admin signing keys: build a single
        // [`AdminKeyStore`] for this principal. The application_id
        // mirrors the AnchorerWorker pattern (`soland.<service_did>`) so
        // operators only manage one secret-storage namespace.
        //
        // In `development_mode` we proactively mint an ephemeral seed
        // for every DID listed in `admin_principal_dids` so smoke-tests
        // can call admin endpoints under the operator DID without any
        // out-of-band provisioning step. Production deployments must
        // pre-populate the platform keystore explicitly — admin DIDs
        // without a provisioned key fall back to
        // `service_admin_signer` at signing time with a sticky-warn.
        let admin_app_id = format!("soland.{}", config.service_did);
        let admin_keystore_inner: Box<dyn contrix_sdk::KeyStore> = if config.use_keystore {
            contrix_sdk::keystore::platform_default_keystore(&admin_app_id)
        } else {
            Box::new(contrix_sdk::keystore::InMemoryKeyStore::new())
        };
        let admin_keystore =
            contrix_sdk::AdminKeyStore::new(admin_app_id.clone(), admin_keystore_inner);
        if config.development_mode {
            for did_str in &config.admin_principal_dids {
                let Ok(did) = Did::new(did_str.clone()) else {
                    tracing::warn!(%did_str, "skipping admin keystore provision: invalid DID shape");
                    continue;
                };
                let has_key = admin_keystore.has_admin_key(&did).unwrap_or(false);
                if !has_key {
                    let mut seed = [0u8; 32];
                    getrandom_seed(&mut seed);
                    if let Err(error) = admin_keystore.store_admin_key(&did, &seed) {
                        tracing::warn!(%error, %did_str,
                            "failed to provision ephemeral admin signing key");
                    } else {
                        tracing::info!(%did_str,
                            "provisioned ephemeral admin signing key (development_mode)");
                    }
                }
            }
        }
        let admin_keystore = Arc::new(admin_keystore);

        // Hydrate Place/Flow/Morph projections from durable
        // persistence so process restart doesn't lose lifecycle state.
        // The write-through path in `routing::events::projection.rs::
        // write_through_projection` keeps these tables in sync as
        // reducer apply mutates the in-memory state.
        let mut hydrated = ProjectionState::new();
        hydrate_projections_from_persistence(persistence.as_ref(), &mut hydrated);

        Self {
            config,
            hlc: ServerHlc::new(&service_did),
            projection: Arc::new(Mutex::new(hydrated)),
            authz: AuthzEngine::new(),
            db,
            persistence,
            object_storage,
            spaces: Arc::new(Mutex::new(spaces)),
            handle_releases: Arc::new(Mutex::new(BTreeMap::new())),
            erased_actors: Arc::new(Mutex::new(BTreeSet::new())),
            notification_read_markers: Arc::new(Mutex::new(BTreeMap::new())),
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
            admin_keystore,
        }
    }
}

/// Fill `out` with cryptographically secure random bytes via
/// `rand::OsRng`. Used by both the boot path (one-shot KeyStore mint) and
/// the rotate-signing-key endpoint.
pub(crate) fn getrandom_seed(out: &mut [u8; 32]) {
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(out);
}

/// Read Place / Flow / Morph projection rows from durable
/// persistence into the supplied `ProjectionState`. Called at
/// `AppState::new` so restart picks up the lifecycle state the
/// write-through path stamped down on the way in. Unknown state
/// strings or invalid rows are silently skipped (logged at warn) —
/// the in-memory state stays authoritative.
fn hydrate_projections_from_persistence(
    persistence: &dyn crate::persistence::PersistenceStore,
    proj: &mut ProjectionState,
) {
    use crate::reducer::{
        FlowProjection, MorphProjection, ObjectLifecycleState, PlaceLifecycleState, PlaceProjection,
    };

    fn parse_place_state(value: &str) -> Option<PlaceLifecycleState> {
        match value {
            "active" => Some(PlaceLifecycleState::Active),
            "archived" => Some(PlaceLifecycleState::Archived),
            "tombstoned" => Some(PlaceLifecycleState::Tombstoned),
            _ => None,
        }
    }
    fn parse_object_state(value: &str) -> Option<ObjectLifecycleState> {
        match value {
            "active" => Some(ObjectLifecycleState::Active),
            "archived" => Some(ObjectLifecycleState::Archived),
            "deleted" => Some(ObjectLifecycleState::Deleted),
            "redacted" => Some(ObjectLifecycleState::Redacted),
            _ => None,
        }
    }

    if let Ok(rows) = persistence.place_projections().snapshot_all() {
        for record in rows {
            let Some(state) = parse_place_state(&record.state) else {
                tracing::warn!(
                    place_id = %record.place_id,
                    state = %record.state,
                    "skipping place projection row with unknown state during hydrate"
                );
                continue;
            };
            proj.places.insert(
                record.place_id.clone(),
                PlaceProjection {
                    place_id: record.place_id,
                    space_id: record.space_id,
                    kind: record.kind,
                    title: record.title,
                    parent_ref: record.parent_ref,
                    rank: record.rank,
                    state,
                    state_changed_at: record.state_changed_at,
                    created_by: record.created_by,
                    created_at: record.created_at,
                    updated_by: record.updated_by,
                    updated_at: record.updated_at,
                },
            );
        }
    }
    if let Ok(rows) = persistence.flow_projections().snapshot_all() {
        for record in rows {
            let Some(state) = parse_object_state(&record.state) else {
                tracing::warn!(
                    flow_id = %record.flow_id,
                    state = %record.state,
                    "skipping flow projection row with unknown state during hydrate"
                );
                continue;
            };
            proj.flows.insert(
                record.flow_id.clone(),
                FlowProjection {
                    flow_id: record.flow_id,
                    space_id: record.space_id,
                    title: record.title,
                    summary: record.summary,
                    state,
                    state_changed_at: record.state_changed_at,
                    created_by: record.created_by,
                    created_at: record.created_at,
                    updated_by: record.updated_by,
                    updated_at: record.updated_at,
                },
            );
        }
    }
    if let Ok(rows) = persistence.morph_projections().snapshot_all() {
        for record in rows {
            let Some(state) = parse_object_state(&record.state) else {
                tracing::warn!(
                    morph_id = %record.morph_id,
                    state = %record.state,
                    "skipping morph projection row with unknown state during hydrate"
                );
                continue;
            };
            proj.morphs.insert(
                record.morph_id.clone(),
                MorphProjection {
                    morph_id: record.morph_id,
                    space_id: record.space_id,
                    morph_type: record.morph_type,
                    title: record.title,
                    state,
                    state_changed_at: record.state_changed_at,
                    created_by: record.created_by,
                    created_at: record.created_at,
                    updated_by: record.updated_by,
                    updated_at: record.updated_at,
                },
            );
        }
    }
}
