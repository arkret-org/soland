use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use zeroize::{Zeroize, Zeroizing};

pub const DEFAULT_MAX_REQUEST_SIZE_BYTES: usize = 1024 * 1024;
pub const DEFAULT_TO_DEVICE_QUEUE_CAPACITY: usize = 10_000;
pub const PQ_HYBRID_TLS_DEPLOYMENT_PROBE_ENV: &str = "SOLAND_PQ_TLS_DEPLOYMENT_PROBE";

/// STUN URL shipped as the [`IceServersConfig::default`] value. A production
/// deployment still advertising this Google public STUN server leaks client
/// candidate-gathering to a third party; surfaced as a hardening warning.
pub const PLACEHOLDER_STUN_URL: &str = "stun:stun.l.google.com:19302";

/// TURN URL shipped as the [`IceServersConfig::default`] value. It points at a
/// non-existent host, so a production deployment still advertising it has no
/// working relay; surfaced as a hardening warning.
pub const PLACEHOLDER_TURN_HOST: &str = "turn.soland.local";

/// Durable key-custody backend used by every Soland KeyStore namespace.
#[derive(Clone, Default)]
pub enum KeyStoreConfig {
    /// No durable key custody. This is valid only for fully in-memory tests and
    /// local development; a persistent database must never use it.
    #[default]
    Disabled,
    /// Native operating-system credential storage for the current user.
    Platform,
    /// Authenticated encrypted file with a separately custodied master key.
    EncryptedFile {
        path: PathBuf,
        master_key: Arc<Zeroizing<[u8; 32]>>,
    },
}

impl fmt::Debug for KeyStoreConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disabled => formatter.write_str("Disabled"),
            Self::Platform => formatter.write_str("Platform"),
            Self::EncryptedFile { path, .. } => formatter
                .debug_struct("EncryptedFile")
                .field("path", path)
                .field("master_key", &"<redacted>")
                .finish(),
        }
    }
}

impl KeyStoreConfig {
    /// Load the backend selector and its backend-specific settings.
    pub fn from_env() -> anyhow::Result<Self> {
        if env_non_empty("SOLAND_USE_KEYSTORE").is_some() {
            anyhow::bail!(
                "SOLAND_USE_KEYSTORE was removed; set SOLAND_KEYSTORE_BACKEND=platform or encrypted_file"
            );
        }

        let backend =
            env_non_empty("SOLAND_KEYSTORE_BACKEND").map(|value| value.to_ascii_lowercase());
        let path = env_non_empty("SOLAND_KEYSTORE_PATH").map(PathBuf::from);
        let master_key_file = env_non_empty("SOLAND_KEYSTORE_MASTER_KEY_FILE");
        let raw_master_key =
            env_non_empty_or_file("SOLAND_KEYSTORE_MASTER_KEY")?.map(Zeroizing::new);

        match backend.as_deref() {
            None => {
                if path.is_some() || raw_master_key.is_some() {
                    anyhow::bail!(
                        "SOLAND_KEYSTORE_BACKEND is required when encrypted-file KeyStore settings are configured"
                    );
                }
                Ok(Self::Disabled)
            }
            Some("platform") => {
                if path.is_some() || raw_master_key.is_some() {
                    anyhow::bail!(
                        "SOLAND_KEYSTORE_PATH and SOLAND_KEYSTORE_MASTER_KEY(_FILE) are only valid with SOLAND_KEYSTORE_BACKEND=encrypted_file"
                    );
                }
                Ok(Self::Platform)
            }
            Some("encrypted_file") => {
                let path = path.ok_or_else(|| {
                    anyhow::anyhow!(
                        "SOLAND_KEYSTORE_PATH is required with SOLAND_KEYSTORE_BACKEND=encrypted_file"
                    )
                })?;
                if master_key_file
                    .as_ref()
                    .is_some_and(|key_path| paths_refer_to_same_file(Path::new(key_path), &path))
                {
                    anyhow::bail!(
                        "SOLAND_KEYSTORE_MASTER_KEY_FILE must be separate from SOLAND_KEYSTORE_PATH"
                    );
                }
                let raw_master_key = raw_master_key.ok_or_else(|| {
                    anyhow::anyhow!(
                        "SOLAND_KEYSTORE_MASTER_KEY or SOLAND_KEYSTORE_MASTER_KEY_FILE is required with SOLAND_KEYSTORE_BACKEND=encrypted_file"
                    )
                })?;
                use base64::Engine as _;
                let mut decoded = Zeroizing::new(
                    base64::engine::general_purpose::STANDARD
                        .decode(raw_master_key.as_bytes())
                        .or_else(|_| {
                            base64::engine::general_purpose::URL_SAFE_NO_PAD
                                .decode(raw_master_key.as_bytes())
                        })
                        .map_err(|error| {
                            anyhow::anyhow!(
                                "SOLAND_KEYSTORE_MASTER_KEY must be base64 (standard or url-safe-no-pad): {error}"
                            )
                        })?,
                );
                if decoded.len() != 32 {
                    anyhow::bail!(
                        "SOLAND_KEYSTORE_MASTER_KEY must decode to exactly 32 bytes (got {})",
                        decoded.len()
                    );
                }
                let mut master_key = [0u8; 32];
                master_key.copy_from_slice(&decoded);
                decoded.zeroize();
                Ok(Self::EncryptedFile {
                    path,
                    master_key: Arc::new(Zeroizing::new(master_key)),
                })
            }
            Some(other) => anyhow::bail!(
                "SOLAND_KEYSTORE_BACKEND must be platform or encrypted_file; got {other}"
            ),
        }
    }

    #[inline]
    pub fn is_durable(&self) -> bool {
        !matches!(self, Self::Disabled)
    }

    pub fn backend_name(&self) -> Option<&'static str> {
        match self {
            Self::Disabled => None,
            Self::Platform => Some("platform"),
            Self::EncryptedFile { .. } => Some("encrypted_file"),
        }
    }

    /// Open one application namespace in the configured durable backend.
    pub fn open(
        &self,
        application_id: &str,
    ) -> anyhow::Result<Option<Box<dyn arkret_core::KeyStore>>> {
        match self {
            Self::Disabled => Ok(None),
            Self::Platform => arkret_keystore::durable_platform_keystore(application_id)
                .map(Some)
                .map_err(|error| anyhow::anyhow!("opening platform KeyStore failed: {error}")),
            Self::EncryptedFile { path, master_key } => {
                let mut key = **master_key.as_ref();
                let store = arkret_keystore::EncryptedFileKeyStore::new(path, application_id, key);
                key.zeroize();
                store
                    .map(|store| Some(Box::new(store) as Box<dyn arkret_core::KeyStore>))
                    .map_err(|error| {
                        anyhow::anyhow!("opening encrypted-file KeyStore failed: {error}")
                    })
            }
        }
    }
}

fn paths_refer_to_same_file(left: &Path, right: &Path) -> bool {
    left == right
        || std::fs::canonicalize(left)
            .ok()
            .zip(std::fs::canonicalize(right).ok())
            .is_some_and(|(left, right)| left == right)
}

fn validate_persistence_key_store(
    database_url: Option<&str>,
    key_store: &KeyStoreConfig,
) -> anyhow::Result<()> {
    if database_url.is_some() && !key_store.is_durable() {
        anyhow::bail!(
            "DATABASE_URL requires a durable KeyStore; set SOLAND_KEYSTORE_BACKEND=platform or encrypted_file"
        );
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub struct AppConfig {
    pub bind: SocketAddr,
    pub metrics_bind: SocketAddr,
    pub public_base_url: String,
    /// Explicit one-shot authorization for a new class-B deployment to mint
    /// its first service identity. The resulting DID is persisted and never
    /// copied back into configuration.
    pub first_provisioning: bool,
    /// Optional TLS certificate PEM path. When both this and
    /// [`tls_key_path`] are configured, soland starts an HTTPS listener using
    /// Salvo's rustls integration instead of plain TCP.
    pub tls_cert_path: Option<PathBuf>,
    /// Optional TLS private-key PEM path paired with [`tls_cert_path`].
    pub tls_key_path: Option<PathBuf>,
    pub database_url: Option<String>,
    pub object_storage: ObjectStorageConfig,
    /// ICE/STUN/TURN servers and credential lifetimes advertised by the
    /// RTC ice-config endpoint. Externalized via `SOLAND_ICE_*` /
    /// `SOLAND_TURN_*` env vars; defaults preserve the historical
    /// hardcoded values.
    pub ice: IceServersConfig,
    /// LiveKit API Key/Secret for `bindings/livekit.md` §2 backend tokens.
    /// When set, the `livekit` media focus issues a standard LiveKit JWT
    /// (`HS256` over `header.payload`, signed with the API Secret) instead
    /// of failing closed. `SOLAND_LIVEKIT_API_KEY` /
    /// `SOLAND_LIVEKIT_API_SECRET` (secret also accepts `_FILE`). v1
    /// supports a single API Key/Secret pair; multi-deployment LiveKit
    /// (one pair per LiveKit cluster, keyed by focus `issuer_kid`) is a
    /// follow-up.
    pub livekit: LiveKitConfig,
    pub cors_allow_origin: Option<String>,
    /// Public Account Authority base URL advertised to browser clients in
    /// `/_arkret/describe.auth_metadata.account_authority`. Registration,
    /// password recovery, passkey, OIDC, and email verification live there;
    /// soland consumes the resulting session grants and may expose DID provider
    /// primitives for trusted server-to-server calls.
    pub account_authority_url: Option<String>,
    /// B-model enrollment authority DID pinned by this Principal Server's
    /// deployment configuration and advertised to account-first clients.
    pub account_authority_enrollment_did: Option<String>,
    /// OAuth/OIDC `client_id` this soland deployment is registered as at the
    /// Auth Server, advertised to browser clients in
    /// `/_arkret/describe.auth_metadata.methods[].oidc.client_id`. The web
    /// client uses it verbatim as the `client_id` in its OIDC authorize
    /// request; coauth keys clients by ULID, so this MUST be the registered
    /// client ULID (e.g. the dev `config.dev.yaml` client). When unset the
    /// OIDC method advertises no `client_id` and the client has nothing valid
    /// to fall back to.
    pub oidc_client_id: Option<String>,
    pub development_mode: bool,
    pub session_grant_introspection_url: Option<String>,
    pub session_grant_introspection_bearer: Option<String>,
    pub did_resolver_allow_methods: Vec<String>,
    /// Enable soland's built-in `did:webvh` provider. This is intended for
    /// ordinary self-hosted deployments and tests: coauth can discover it via
    /// `/_arkret/root/identity/describe`, register a user DID through soland, then
    /// resolve the resulting document through soland's local identity store.
    pub embedded_webvh_provider_enabled: bool,
    /// Shared bearer token required to write embedded `did:webvh` records.
    /// Read endpoints remain public because DID resolution needs them, but
    /// registration must be restricted to the trusted registration service
    /// (normally coauth).
    pub embedded_webvh_registration_bearer: Option<String>,
    /// Optional external `did:webvh` provider URL. This can point at StarID or
    /// any compatible provider. It records admin intent and is surfaced in
    /// `/identity/describe` even when the boot probe fails.
    pub external_webvh_provider_url: Option<String>,
    /// Registration credential for using the configured external WebVH
    /// service as this deployment's Service Identity Provider. When present,
    /// service identity is class-A/provider-backed and first provisioning does
    /// not require `SOLAND_FIRST_PROVISIONING`.
    pub external_webvh_registration_bearer: Option<String>,
    /// Runtime liveness for the external provider. `true` only when the
    /// external provider's `/describe` probe succeeds at boot.
    pub external_webvh_provider_active: bool,
    /// Provider id coauth should preselect. When unset, soland chooses
    /// `soland.embedded` if the embedded provider is enabled, otherwise the
    /// first configured external provider.
    pub default_webvh_provider_id: Option<String>,
    /// JWS replay protection window in seconds.
    /// Move and Seal signatures whose signed `hlc` is older than
    /// `now - replay_window_seconds` OR newer than `now +
    /// replay_window_seconds` are rejected.
    ///
    /// Default 300s = 5 min — matches the Arkret spec recommendation in
    /// `signatures-and-replay.md`. Set to `0` to disable (dev / tests
    /// using fixed-time fixtures rely on this; production deployments
    /// MUST keep this > 0).
    pub jws_replay_window_seconds: u64,
    /// Per-cell-family replay-window overrides.
    /// Some cell families have different freshness requirements than the
    /// global default — e.g. `ak.component.notary.v1` (Realm-wide
    /// authority cell) needs a much tighter window than chat messages.
    /// When a Move's `effects[]` touch any cell whose family appears in
    /// this map, the **minimum** override across touched families wins
    /// (most-restrictive). Falls back to `jws_replay_window_seconds` for
    /// families without an override.
    ///
    /// Production default (built by [`AppConfig::default_replay_overrides`]):
    /// - `ak.component.notary.v1` → 60s (very fresh — Realm-wide pause risk)
    /// - `ak.component.mls.epoch.v1` → 60s (E2EE fork risk)
    /// - `ak.component.consent.grant.v1` → 120s (capability-equivalent)
    /// - `ak.component.capability.grant.v1` → 120s
    /// - `ak.component.capability.delegate.v1` → 120s
    /// - `ak.component.capability.derived.v1` → 120s
    pub jws_replay_window_per_family: std::collections::BTreeMap<&'static str, u64>,
    /// Base64-encoded 32-byte ed25519 seed for the NotaryWorker
    /// signing identity (env `SOLAND_NOTARY_SIGNING_KEY`). When `Some(_)`
    /// the worker uses a deterministic ed25519-dalek signing key derived
    /// from this seed; when `None` the worker boots with an in-process
    /// random ephemeral key and a sticky-warn log line on every signing
    /// pass, matching the [`NotarySigningKeyOrigin::Ephemeral`] branch.
    ///
    /// Loading is identical to coauth's session-grant signing-key pattern
    /// — the env var holds the raw seed, base64-standard-padded; bad shape
    /// fails fast at startup with a clear error.
    pub notary_signing_key_seed: Option<[u8; 32]>,
    /// Durable key custody shared by service identity, notary, and admin
    /// KeyStore namespaces. Signing and WebVH
    /// control secrets are addressed exclusively by the opaque KeyRefs in
    /// the verified `LocalServiceIdentity`; AppState neither derives a key id
    /// from the service DID nor independently mints a runtime signer.
    ///
    /// When disabled, an explicit `SOLAND_NOTARY_SIGNING_KEY` may supply the
    /// signing secret, but WebVH control-key custody still requires a durable
    /// KeyStore. Service signing-key rotation fails closed until the WebVH
    /// history, DID document, stored identity, KeyStore, and recovery bundle
    /// can be updated as one recoverable transition.
    pub key_store: KeyStoreConfig,
    /// Federation fanout topology. The on-the-wire shape is `ak.peer.events.command.submit`
    /// under `/_arkret/peer/events`; the topology only changes which peer set
    /// receives accepted Event fanout.
    ///
    /// - [`FederationFanoutTopology::Mesh`] — broadcast each accepted Event to every known peer.
    /// - [`FederationFanoutTopology::Hub`] — push only to a single configured upstream hub; rely
    ///   on the hub for outbound dissemination.
    pub federation_fanout_topology: FederationFanoutTopology,
    /// Federation peer endpoints the outbound layer considers as broadcast
    /// targets (mesh) or hub upstream (hub). Endpoint-only entries are
    /// resolved through `/_arkret/describe`; the discovered service DID is
    /// kept in runtime state rather than copied into deployment config. Empty
    /// disables federation outbound.
    pub federation_peers: Vec<String>,
    /// G3.S0 — when true (default), `main.rs` spawns the
    /// `FederationDispatcher` background worker that drains the
    /// `federation_outbox` table and POSTs each pending row to its peer
    /// with `Idempotency-Key` + `Content-Digest` headers. Set
    /// `SOLAND_FEDERATION_OUTBOUND=0` to disable for integration tests
    /// that don't want background HTTP traffic (the in-process `enqueue`
    /// path still writes outbox rows so cotest can observe the boundary).
    pub federation_outbound_enabled: bool,
    /// Federation replica / observer admission posture (member-delivery-binding.md
    /// §4 delivery-binding gate). The inbound delivery-binding gate normally
    /// fails closed when a push targets a Realm this server already hosts but is
    /// the effective `delivery_binding.recipient_service_id` for zero local
    /// members — there is then no local member binding the asserted frontier can
    /// correspond to. A conservative server (default `false`) rejects such
    /// pushes with `delivery_binding_stale`. A server explicitly deployed as a
    /// federation replica / observer (holds a Realm copy with no locally-homed
    /// members) sets this `true` to admit those pushes as pure replication;
    /// there is no locally-bound member that could be stale, so the gate has
    /// nothing to protect. Env: `SOLAND_FEDERATION_REPLICA_OBSERVER`
    /// (default `false`).
    pub federation_replica_observer: bool,
    /// Default page size for `GET /_soland/admin/cells` and the rest of
    /// the admin paginated read surfaces when the caller omits `limit`.
    /// Env: `SOLAND_ADMIN_PAGE_LIMIT` (default `100`).
    pub admin_default_page_limit: usize,
    /// Hard cap on `limit` query for the admin paginated read surfaces;
    /// requests asking for a larger page are clamped down. Defends
    /// against a misbehaving client exhausting in-memory projection state.
    /// Env: `SOLAND_ADMIN_MAX_PAGE_LIMIT` (default `1000`).
    pub admin_max_page_limit: usize,
    /// Principal DIDs allowed to call `GET /_soland/admin/{resource}` and the
    /// other production-gated admin read surfaces when `development_mode` is
    /// false. Empty (default) keeps the previous "dev-mode only" posture for
    /// these endpoints. Env: `SOLAND_ADMIN_PRINCIPAL_DIDS` (comma-separated).
    pub admin_principal_dids: Vec<String>,
    /// Maximum unacknowledged to-device messages retained per
    /// `(recipient_principal_id, device_id)`. Older messages beyond this
    /// capacity are dropped, and the device lost watermark is advanced so the
    /// next to-device response can carry `lost=true`.
    /// Env: `SOLAND_TO_DEVICE_QUEUE_CAPACITY` (default 10_000).
    pub to_device_queue_capacity: usize,
    /// Max age (in seconds) a cached outbound push bridge contract is allowed
    /// to keep its trusted state without re-verification. Snapshots whose
    /// `freshness_at` is older than this are treated as stale on cache_hit and
    /// trigger a fresh remote fetch (and downgrade to `trust_level=stale` if
    /// the upstream is unreachable). Default 900s (15 min).
    /// Env: `SOLAND_PUSH_BRIDGE_CACHE_TTL_SECS`.
    pub push_bridge_cache_ttl_seconds: u64,
    /// Service DIDs allowed to be promoted from `trust_level=pending` to
    /// `trusted` on snapshot import. Empty (default) means imports stay at
    /// `pending` and have to be promoted manually via the live-fetch path.
    /// Env: `SOLAND_PUSH_BRIDGE_TRUSTED_SERVICE_IDS` (comma-separated).
    pub push_bridge_trusted_service_ids: Vec<String>,
    /// Resumable (tus) blob upload — staging directory for in-progress
    /// upload parts before they are completed into the blob store. See
    /// spec crypto-media/media-and-blob.md §2.1.
    /// Env: `SOLAND_RESUMABLE_UPLOAD_DIR` (default `./soland-resumable-uploads`).
    pub resumable_upload_dir: PathBuf,
    /// Resumable (tus) blob upload — maximum lifetime of an incomplete
    /// upload part, in seconds. Expired parts are garbage-collected and
    /// never produce a referencable `blob_ref`. Advertised in
    /// `describe.limits.resumable_upload_incomplete_ttl_seconds`.
    /// Env: `SOLAND_RESUMABLE_UPLOAD_TTL_SECS` (default 86_400 = 24h).
    pub resumable_upload_incomplete_ttl_seconds: u64,
    /// MAL-11 compaction: minimum age (seconds) before a Seal is
    /// prune-eligible. Younger Seals must not be pruned even when a
    /// compaction Seal has witnessed them — gives slow federation peers
    /// time to backfill before history is dropped.
    /// Env: `SOLAND_COMPACTION_MIN_SEAL_AGE_SECS` (default 604_800 = 7 days).
    pub seal_compaction_min_age_seconds: u64,
    /// MAL-11 compaction: minimum number of compaction Seals between
    /// the prune candidate and the current leaf set.
    /// Env: `SOLAND_COMPACTION_MIN_WITNESSES` (default 1).
    pub compaction_min_witnesses: u32,
    /// MAL-11 compaction: refuse to prune the genesis Seal when true.
    /// Env: `SOLAND_COMPACTION_PRESERVE_GENESIS` (default true).
    pub compaction_preserve_genesis: bool,
    /// MAL-11 compaction: refuse to prune fork-point Seals (more than
    /// one direct successor) when true. Keeps the prune walk
    /// conservative by default.
    /// Env: `SOLAND_COMPACTION_PRUNE_ONLY_SINGLETON_SUCCESSORS` (default true).
    pub compaction_prune_only_singleton_successors: bool,
    /// MAL-11 compaction prune walk: interval between background prune
    /// passes, in seconds. Zero (or unset) disables the worker entirely —
    /// MAL-11 prune then runs only via the explicit
    /// `POST /_soland/admin/realms/{realm_id}/seal-dag/prune?seal_id=...`
    /// endpoint. When enabled, the worker walks every live Realm's
    /// seal DAG, evaluates each candidate against
    /// [`compaction_policy`], and prunes eligible Seals up to
    /// `compaction_prune_walk_per_realm_limit` per Realm per pass.
    /// Env: `SOLAND_COMPACTION_PRUNE_WALK_INTERVAL_SECS` (default 0 = disabled).
    pub compaction_prune_walk_interval_seconds: u64,
    /// MAL-11 compaction prune walk: maximum number of prunes the worker
    /// will perform per Realm per pass. Bounds I/O against very large
    /// DAGs; further candidates are picked up on subsequent ticks.
    /// Env: `SOLAND_COMPACTION_PRUNE_WALK_PER_REALM_LIMIT` (default 50).
    pub compaction_prune_walk_per_realm_limit: usize,
    /// Round R2/R3 (T08) — deployment trust domain id, used to bind
    /// `ak.cross_signing.reset` events to this Principal Server so the
    /// same proof bytes cannot be replayed cross-domain. Loaded from
    /// `SOLAND_TRUST_DOMAIN` (must match `ak:trust_domain:<scope>`,
    /// scope = lowercase alphanumerics/dot/dash/underscore/colon ≤128 chars).
    /// Defaults to `ak:trust_domain:<host_of_service_id>`.
    pub trust_domain: String,
    /// Deployment/admin upper bound for invite/contact receive policies.
    /// Constraints can only reduce holder reachability. Loaded from
    /// `SOLAND_RECEIVE_POLICY_*` env vars and advertised on ServiceDescribe.
    pub receive_policy_constraints: Option<arkret_core::ReceivePolicyConstraints>,
    /// When true, `AppState::new` seeds a deterministic demo Realm
    /// (`ak:realm:0196419b-...`), demo account (`did:web:alice.example`),
    /// and matching space_meta record on boot. Off by default so
    /// production deployments don't ship a globally-shared demo Realm
    /// that collides across federated peers. Test harnesses opt in via
    /// `test_config()` to keep their fixture IDs stable.
    /// Env: `SOLAND_SEED_DEMO_DATA` (default false).
    pub seed_demo_data: bool,
    /// G3.S9 — when true, soland claims `ak.profile.sovereign_enclave.v1`
    /// on `/server/describe` and enforces the enclave invariants
    /// (`routing::extensions::sovereign::assert_enclave_invariants`):
    /// outbound federation OFF, DID resolver method allow-list
    /// non-empty, every outbound HTTP call gated through the shared
    /// [`crate::security`] egress validation layer.
    /// Env: `SOLAND_SOVEREIGN_ENCLAVE` (default false).
    pub sovereign_enclave_enabled: bool,
    /// G3.S9 — host allow-list for outbound HTTP when the enclave
    /// profile is enabled. Hosts are matched case-insensitively.
    /// Comma-separated env var
    /// `SOLAND_SOVEREIGN_ENCLAVE_ALLOWED_OUTBOUND_HOSTS`.
    pub sovereign_enclave_allowed_outbound_hosts: Vec<String>,
    /// When true, soland claims the `ak.profile.candidate.join_policy.v1`
    /// candidate profile and exposes the product-local join-policy
    /// member-application read surface
    /// (`GET /_soland/self/realms/{realm_id}/applications`,
    /// `org.arkret.soland.member_application.query.list`). `member.application`
    /// is a spec candidate concept (`governance/join-policy.md` §7.2) that MUST
    /// stay off the `/_arkret/...` protocol root and out of the `ak.*` namespace
    /// until formally registered; the read surface is fail-closed (404) unless
    /// this profile is declared.
    /// Env: `SOLAND_CANDIDATE_JOIN_POLICY` (default false).
    pub candidate_join_policy_enabled: bool,
    /// Stream-F (Wave 2C) — cross-Principal-Server erasure-receipt
    /// propagation window in milliseconds. After a
    /// `ak.audit.erasure_receipt` is accepted, the federation fanout
    /// worker waits up to this many ms for every peer to acknowledge.
    /// Peers that don't respond inside the window flip the receipt's
    /// top-level `fanout_status` to `incomplete`. Spec
    /// `realm-and-space.md` §2.5.2: default 7 days (604_800_000 ms).
    /// Env: `SOLAND_ERASURE_PROPAGATION_WINDOW_MS`.
    pub erasure_propagation_window_ms: u64,
    /// P5 (5.4) — structured-logging output format. Defaults to
    /// [`LogFormat::Json`] in production (`SOLAND_DEVELOPMENT_MODE=false`)
    /// and [`LogFormat::Plain`] in development. Override at any time via
    /// `SOLAND_LOG_FORMAT=json|plain`. JSON output is the format on-call
    /// runbooks assume (the `runbook.md` log-search recipes use
    /// `jq`-friendly field names).
    pub log_format: LogFormat,
}

/// Tracing-subscriber output format. See [`AppConfig::log_format`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogFormat {
    /// Human-readable ANSI-decorated logs. Default in development mode.
    Plain,
    /// One JSON object per event. Default in production so
    /// log-aggregation pipelines (Loki, OpenSearch, Cloud Logging)
    /// see structured fields without bespoke parsers.
    Json,
}

impl LogFormat {
    pub fn from_env(development_mode: bool) -> Self {
        match std::env::var("SOLAND_LOG_FORMAT").ok().as_deref() {
            Some("json") | Some("JSON") => LogFormat::Json,
            Some("plain") | Some("PLAIN") | Some("text") | Some("TEXT") => LogFormat::Plain,
            _ => {
                if development_mode {
                    LogFormat::Plain
                } else {
                    LogFormat::Json
                }
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObjectStorageConfig {
    Local {
        root: PathBuf,
        prefix: String,
    },
    S3Compatible {
        bucket: String,
        region: String,
        endpoint: Option<String>,
        access_key_id: Option<String>,
        secret_access_key: Option<String>,
        session_token: Option<String>,
        prefix: String,
        force_path_style: bool,
        allow_http: bool,
        skip_signature: bool,
    },
}

impl ObjectStorageConfig {
    pub fn local(root: impl Into<PathBuf>) -> Self {
        Self::Local {
            root: root.into(),
            prefix: String::new(),
        }
    }

    pub fn backend_name(&self) -> &'static str {
        match self {
            Self::Local { .. } => "local",
            Self::S3Compatible { .. } => "s3",
        }
    }

    pub fn log_target(&self) -> String {
        match self {
            Self::Local { root, prefix } => {
                if prefix.is_empty() {
                    root.display().to_string()
                } else {
                    format!("{}:{}", root.display(), prefix)
                }
            }
            Self::S3Compatible {
                bucket,
                endpoint,
                prefix,
                ..
            } => {
                let endpoint = endpoint.as_deref().unwrap_or("aws-region-endpoint");
                if prefix.is_empty() {
                    format!("{endpoint}/{bucket}")
                } else {
                    format!("{endpoint}/{bucket}/{prefix}")
                }
            }
        }
    }
}

/// ICE/STUN/TURN configuration advertised by
/// `POST /_arkret/self/rtc/ice-config`. Externalized from hardcoded
/// defaults so operators can point clients at their own STUN/TURN
/// infrastructure and tune credential lifetimes per deployment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IceServersConfig {
    /// STUN server URLs advertised to clients (e.g. `stun:host:3478`).
    pub stun_urls: Vec<String>,
    /// TURN server URLs advertised to clients (e.g.
    /// `turn:host:3478?transport=udp`).
    pub turn_urls: Vec<String>,
    /// Lifetime in seconds of an issued ICE configuration / TURN
    /// credential before clients must request a refresh.
    pub ttl_seconds: u32,
    /// Lead time in seconds before `ttl_seconds` at which clients should
    /// proactively refresh the ICE configuration.
    pub refresh_lead_seconds: u32,
    /// Rotation window in seconds for the TURN shared secret. Reserved for
    /// time-windowed TURN credential derivation.
    pub turn_secret_rotation_window_seconds: u64,
    /// Optional REST-style (draft-uberti) TURN shared secret. The advertised
    /// TURN credential is `base64(HMAC-SHA256(turn_shared_secret, username))`
    /// over the `<expiry-unix>:<pseudonym>` username, so an external coturn
    /// configured with the same secret validates it. When unset, a
    /// deployment-stable fallback derived from the notary signing seed is used.
    pub turn_shared_secret: Option<String>,
}

impl Default for IceServersConfig {
    fn default() -> Self {
        Self {
            stun_urls: vec!["stun:stun.l.google.com:19302".to_owned()],
            turn_urls: vec!["turn:turn.soland.local:3478?transport=udp".to_owned()],
            ttl_seconds: 300,
            refresh_lead_seconds: 75,
            turn_secret_rotation_window_seconds: 86_400,
            turn_shared_secret: None,
        }
    }
}

/// LiveKit API credentials used to mint `bindings/livekit.md` §2 backend
/// tokens (standard LiveKit JWT, `HS256` signed with the API Secret).
///
/// v1 carries a single `(api_key, api_secret)` pair. Deployments that run
/// multiple LiveKit clusters MUST map each focus `issuer_kid` to its own
/// API Key/Secret; that multi-pair mapping is intentionally deferred and a
/// single configured pair is matched against the focus `issuer_kid` at
/// sign time.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LiveKitConfig {
    /// LiveKit API Key. In the LiveKit binding the media focus
    /// `issuer_kid` is the LiveKit API Key; the token issuer fails closed
    /// when the focus-declared `issuer_kid` does not equal this value.
    pub api_key: Option<String>,
    /// LiveKit API Secret. HMAC-SHA256 signing key for the JWT. Never
    /// surfaced in any public cell, `/health`, or describe payload.
    pub api_secret: Option<String>,
}

/// Load LiveKit API credentials. The secret accepts the `_FILE` indirection
/// so operators can mount it via Kubernetes / Docker / systemd secrets.
fn load_livekit_config() -> anyhow::Result<LiveKitConfig> {
    let api_key = env_non_empty("SOLAND_LIVEKIT_API_KEY");
    let api_secret = env_non_empty_or_file("SOLAND_LIVEKIT_API_SECRET")?;
    Ok(LiveKitConfig {
        api_key,
        api_secret,
    })
}

/// Federation fanout topology. Selected at config-load
/// time via `SOLAND_FEDERATION_FANOUT_TOPOLOGY` env var (`mesh` | `hub`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FederationFanoutTopology {
    /// Default — broadcast every accepted Event to every peer in
    /// [`AppConfig::federation_peers`].
    Mesh,
    /// Push to a single upstream hub. The first entry in
    /// [`AppConfig::federation_peers`] is the hub.
    Hub,
}

impl FederationFanoutTopology {
    pub fn from_env_value(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "hub" => Self::Hub,
            _ => Self::Mesh,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Mesh => "mesh",
            Self::Hub => "hub",
        }
    }
}

/// Provenance tag for the NotaryWorker's signing key. Surfaced
/// on each signing pass so logs flag the dev-only ephemeral path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotarySigningKeyOrigin {
    /// Loaded from `SOLAND_NOTARY_SIGNING_KEY` (production-grade
    /// persistent identity).
    Configured,
    /// In-process random seed — fine for tests, **never** for production:
    /// every restart issues Seals under a brand-new DID, breaking
    /// signature-chain trust.
    Ephemeral,
}

impl AppConfig {
    /// Spec-recommended per-cell-family replay-window overrides.
    /// Tighter windows for safety-critical / authority cells; the global
    /// default still applies to everything else.
    pub fn default_replay_overrides() -> std::collections::BTreeMap<&'static str, u64> {
        let mut m = std::collections::BTreeMap::new();
        m.insert("ak.component.notary.v1", 60);
        m.insert("ak.component.mls.epoch.v1", 60);
        m.insert("ak.component.consent.grant.v1", 120);
        m.insert("ak.component.capability.grant.v1", 120);
        m.insert("ak.component.capability.delegate.v1", 120);
        m.insert("ak.component.capability.derived.v1", 120);
        m
    }
}

impl AppConfig {
    /// Single source of truth for test configs. Defaults take the
    /// production posture (`development_mode = false`, replay-window
    /// enforcement and per-family overrides on, demo seeding off);
    /// individual tests opt into relaxed settings explicitly via
    /// struct-update syntax:
    ///
    /// ```ignore
    /// let config = AppConfig {
    ///     development_mode: true,
    ///     jws_replay_window_seconds: 0,
    ///     ..AppConfig::test_default()
    /// };
    /// ```
    pub fn test_default() -> Self {
        Self {
            bind: "127.0.0.1:0".parse().unwrap(),
            metrics_bind: "127.0.0.1:0".parse().unwrap(),
            public_base_url: "http://server".to_owned(),
            first_provisioning: false,
            tls_cert_path: None,
            tls_key_path: None,
            database_url: None,
            object_storage: ObjectStorageConfig::local(
                std::env::temp_dir().join("soland-test-blobs"),
            ),
            ice: IceServersConfig::default(),
            livekit: LiveKitConfig::default(),
            cors_allow_origin: None,
            account_authority_url: None,
            account_authority_enrollment_did: None,
            oidc_client_id: None,
            development_mode: false,
            session_grant_introspection_url: None,
            session_grant_introspection_bearer: None,
            // Test fixtures intentionally allow bare `did:web` — the spec
            // conformance vectors use it. The production default
            // (`default_did_resolver_allow_methods`) is webvh-only.
            did_resolver_allow_methods: vec!["web".to_owned(), "key".to_owned(), "uuid".to_owned()],
            embedded_webvh_provider_enabled: false,
            embedded_webvh_registration_bearer: None,
            external_webvh_provider_url: None,
            external_webvh_registration_bearer: None,
            external_webvh_provider_active: false,
            default_webvh_provider_id: None,
            jws_replay_window_seconds: 300,
            jws_replay_window_per_family: Self::default_replay_overrides(),
            notary_signing_key_seed: None,
            key_store: KeyStoreConfig::Disabled,
            federation_fanout_topology: FederationFanoutTopology::Mesh,
            federation_peers: Vec::new(),
            // Off so test binaries never spawn background federation HTTP
            // traffic; the in-process enqueue path still writes outbox rows.
            federation_outbound_enabled: false,
            federation_replica_observer: false,
            admin_default_page_limit: 100,
            admin_max_page_limit: 1000,
            admin_principal_dids: Vec::new(),
            to_device_queue_capacity: 10_000,
            push_bridge_cache_ttl_seconds: 900,
            push_bridge_trusted_service_ids: Vec::new(),
            resumable_upload_dir: PathBuf::from("./soland-resumable-uploads"),
            resumable_upload_incomplete_ttl_seconds: 86_400,
            seal_compaction_min_age_seconds: 604_800,
            compaction_min_witnesses: 1,
            compaction_preserve_genesis: true,
            compaction_prune_only_singleton_successors: true,
            compaction_prune_walk_interval_seconds: 0,
            compaction_prune_walk_per_realm_limit: 50,
            seed_demo_data: false,
            trust_domain: "ak:trust_domain:soland.local".to_owned(),
            receive_policy_constraints: None,
            sovereign_enclave_enabled: false,
            sovereign_enclave_allowed_outbound_hosts: Vec::new(),
            candidate_join_policy_enabled: false,
            erasure_propagation_window_ms: 604_800_000,
            log_format: LogFormat::Plain,
        }
    }
}

impl AppConfig {
    pub fn from_env_and_args() -> anyhow::Result<Self> {
        let bind = arg_value("--bind")
            .or_else(|| std::env::var("SOLAND_BIND").ok())
            .unwrap_or_else(|| "127.0.0.1:8698".to_owned())
            .parse()?;
        let metrics_bind = std::env::var("SOLAND_METRICS_BIND")
            .unwrap_or_else(|_| "127.0.0.1:9090".to_owned())
            .parse()?;
        let public_base_url =
            std::env::var("SOLAND_PUBLIC_BASE_URL").unwrap_or_else(|_| format!("http://{bind}"));
        if env_non_empty("SOLAND_SERVICE_ID").is_some() {
            anyhow::bail!(
                "SOLAND_SERVICE_ID is no longer accepted: service identity is resolved from the \
                 durable service_identity record, Provider registration mapping, or verified \
                 identity bundle"
            );
        }
        if env_non_empty("SOLAND_BOOTSTRAP_SERVICE_IDENTITY").is_some() {
            anyhow::bail!(
                "SOLAND_BOOTSTRAP_SERVICE_IDENTITY was removed; use the one-shot \
                 --first-provisioning flag or SOLAND_FIRST_PROVISIONING=1"
            );
        }
        let first_provisioning = std::env::args().any(|arg| arg == "--first-provisioning")
            || env_bool("SOLAND_FIRST_PROVISIONING")?.unwrap_or(false);
        let tls_cert_path = env_non_empty("SOLAND_TLS_CERT_PATH").map(PathBuf::from);
        let tls_key_path = env_non_empty("SOLAND_TLS_KEY_PATH").map(PathBuf::from);
        if tls_cert_path.is_some() != tls_key_path.is_some() {
            anyhow::bail!("SOLAND_TLS_CERT_PATH and SOLAND_TLS_KEY_PATH must be set together");
        }
        let database_url = std::env::var("DATABASE_URL")
            .ok()
            .filter(|value| !value.trim().is_empty());
        let object_storage = load_object_storage_config()?;
        let ice = load_ice_servers_config()?;
        let livekit = load_livekit_config()?;
        let account_authority_url = env_non_empty("SOLAND_ACCOUNT_AUTHORITY_URL");
        let account_authority_enrollment_did =
            env_non_empty("SOLAND_ACCOUNT_AUTHORITY_ENROLLMENT_DID");
        if account_authority_url.is_some() != account_authority_enrollment_did.is_some() {
            anyhow::bail!(
                "SOLAND_ACCOUNT_AUTHORITY_URL and SOLAND_ACCOUNT_AUTHORITY_ENROLLMENT_DID must be set together"
            );
        }
        if let Some(value) = account_authority_enrollment_did.as_deref() {
            arkret_core::Did::new(value.to_owned()).map_err(|error| {
                anyhow::anyhow!("SOLAND_ACCOUNT_AUTHORITY_ENROLLMENT_DID is invalid: {error}")
            })?;
        }
        let oidc_client_id = env_non_empty("SOLAND_OAUTH_CLIENT_ID");
        // Default to a production-safe posture (no `dev_login`, no relaxed DID
        // validation, no admin snapshot endpoints). Local development must opt
        // in explicitly via `SOLAND_DEVELOPMENT_MODE=true`.
        let development_mode = std::env::var("SOLAND_DEVELOPMENT_MODE")
            .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes"))
            .unwrap_or(false);
        // Production first provisioning is authorized later, after the
        // durable identity stores are open, by `first_provisioning`.
        // Development mode may provision automatically. Config never carries
        // or pins the resulting DID (identity-did.md §3.7 I-2/I-3).
        // CORS posture per api-conventions.md §10 — browser clients SHOULD be
        // able to reach us via preflight. Three shapes:
        //   - env unset, production mode → `None` (no CORS handler at all; operator must opt in
        //     explicitly for browser access)
        //   - env unset, development mode → defaults to `Some("*")`, the spec-recommended
        //     permissive default for local / loopback work so plain `cargo run` of soland is
        //     reachable from a inkson dev server without extra env wiring
        //   - env set → use as-is. `"*"` installs the permissive (mirror origin, no credentials)
        //     handler; any other value is treated as an explicit origin allow-list and installs the
        //     credentialed handler. See `routing::cors_handler_for_config`.
        let cors_allow_origin = std::env::var("SOLAND_CORS_ALLOW_ORIGIN")
            .ok()
            .map(|v| v.trim().to_owned())
            .filter(|v| !v.is_empty())
            .or_else(|| development_mode.then(|| "*".to_owned()));
        let session_grant_introspection_url =
            env_non_empty("SOLAND_SESSION_GRANT_INTROSPECTION_URL");
        let session_grant_introspection_bearer =
            env_non_empty_or_file("SOLAND_SESSION_GRANT_INTROSPECTION_BEARER")?;
        let did_resolver_allow_methods = env_csv("SOLAND_DID_RESOLVER_ALLOW_METHODS")
            .unwrap_or_else(default_did_resolver_allow_methods);
        let embedded_webvh_provider_enabled =
            env_bool("SOLAND_EMBEDDED_WEBVH_PROVIDER_ENABLED")?.unwrap_or(true);
        let embedded_webvh_registration_bearer =
            env_non_empty_or_file("SOLAND_EMBEDDED_WEBVH_REGISTRATION_BEARER")?;
        let external_webvh_provider_url = env_non_empty("SOLAND_EXTERNAL_WEBVH_PROVIDER_URL");
        let external_webvh_registration_bearer =
            env_non_empty_or_file("SOLAND_EXTERNAL_WEBVH_REGISTRATION_BEARER")?;
        if external_webvh_registration_bearer.is_some() && external_webvh_provider_url.is_none() {
            anyhow::bail!(
                "SOLAND_EXTERNAL_WEBVH_PROVIDER_URL is required when \
                 SOLAND_EXTERNAL_WEBVH_REGISTRATION_BEARER is configured"
            );
        }
        let default_webvh_provider_id = env_non_empty("SOLAND_DEFAULT_WEBVH_PROVIDER_ID");
        // 0 disables replay-window enforcement; default 5 min per spec.
        let jws_replay_window_seconds = std::env::var("SOLAND_JWS_REPLAY_WINDOW_SECONDS")
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .unwrap_or(300);
        // T3 — 0 disables Move/Seal replay-window enforcement. Fine for
        // fixed-time test fixtures (dev mode); a production misconfiguration.
        if !development_mode && jws_replay_window_seconds == 0 {
            anyhow::bail!(
                "SOLAND_JWS_REPLAY_WINDOW_SECONDS must be > 0 when SOLAND_DEVELOPMENT_MODE is false (0 disables replay protection)"
            );
        }
        let notary_signing_key_seed = load_notary_signing_key_seed()?;
        let key_store = KeyStoreConfig::from_env()?;
        validate_persistence_key_store(database_url.as_deref(), &key_store)?;
        // T2 — without a persistent notary seed (env or KeyStore) the worker
        // mints a fresh ephemeral ed25519 identity on every restart, which
        // breaks the Seal signature chain. Match the `agent_audit_binding`
        // fail-fast posture; the notary key is at least as critical.
        if !development_mode && notary_signing_key_seed.is_none() && !key_store.is_durable() {
            anyhow::bail!(
                "SOLAND_NOTARY_SIGNING_KEY (or a durable SOLAND_KEYSTORE_BACKEND) is required when SOLAND_DEVELOPMENT_MODE is false; an ephemeral notary key breaks the Seal signature chain across restarts"
            );
        }
        let federation_fanout_topology = std::env::var("SOLAND_FEDERATION_FANOUT_TOPOLOGY")
            .ok()
            .map(|value| FederationFanoutTopology::from_env_value(&value))
            .unwrap_or(FederationFanoutTopology::Mesh);
        let federation_peers = std::env::var("SOLAND_FEDERATION_PEERS")
            .ok()
            .map(|value| {
                value
                    .split(',')
                    .map(|v| v.trim().to_owned())
                    .filter(|v| !v.is_empty())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        // G3.S0 — outbound dispatcher toggle. Defaults to enabled so the
        // background worker drains the outbox; tests that don't want
        // unsolicited HTTP traffic set `SOLAND_FEDERATION_OUTBOUND=0`.
        let federation_outbound_enabled = env_bool("SOLAND_FEDERATION_OUTBOUND")?.unwrap_or(true);
        let federation_replica_observer =
            env_bool("SOLAND_FEDERATION_REPLICA_OBSERVER")?.unwrap_or(false);
        let admin_default_page_limit = std::env::var("SOLAND_ADMIN_PAGE_LIMIT")
            .ok()
            .and_then(|value| value.trim().parse::<usize>().ok())
            .filter(|n| *n > 0)
            .unwrap_or(100);
        let admin_max_page_limit = std::env::var("SOLAND_ADMIN_MAX_PAGE_LIMIT")
            .ok()
            .and_then(|value| value.trim().parse::<usize>().ok())
            .filter(|n| *n > 0)
            .unwrap_or(1000)
            .max(admin_default_page_limit);
        let admin_principal_dids = std::env::var("SOLAND_ADMIN_PRINCIPAL_DIDS")
            .ok()
            .map(|value| {
                value
                    .split(',')
                    .map(|v| v.trim().to_owned())
                    .filter(|v| !v.is_empty())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let to_device_queue_capacity = std::env::var("SOLAND_TO_DEVICE_QUEUE_CAPACITY")
            .ok()
            .and_then(|value| value.trim().parse::<usize>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(DEFAULT_TO_DEVICE_QUEUE_CAPACITY);
        let push_bridge_cache_ttl_seconds = std::env::var("SOLAND_PUSH_BRIDGE_CACHE_TTL_SECS")
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .unwrap_or(900);
        let push_bridge_trusted_service_ids =
            std::env::var("SOLAND_PUSH_BRIDGE_TRUSTED_SERVICE_IDS")
                .ok()
                .map(|value| {
                    value
                        .split(',')
                        .map(|v| v.trim().to_owned())
                        .filter(|v| !v.is_empty())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
        let resumable_upload_dir = env_non_empty("SOLAND_RESUMABLE_UPLOAD_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("./soland-resumable-uploads"));
        let resumable_upload_incomplete_ttl_seconds =
            std::env::var("SOLAND_RESUMABLE_UPLOAD_TTL_SECS")
                .ok()
                .and_then(|value| value.trim().parse::<u64>().ok())
                .unwrap_or(86_400)
                .max(60);
        let seal_compaction_min_age_seconds = std::env::var("SOLAND_COMPACTION_MIN_SEAL_AGE_SECS")
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .unwrap_or(604_800);
        let compaction_min_witnesses = std::env::var("SOLAND_COMPACTION_MIN_WITNESSES")
            .ok()
            .and_then(|value| value.trim().parse::<u32>().ok())
            .unwrap_or(1);
        let compaction_preserve_genesis =
            env_bool("SOLAND_COMPACTION_PRESERVE_GENESIS")?.unwrap_or(true);
        let compaction_prune_only_singleton_successors =
            env_bool("SOLAND_COMPACTION_PRUNE_ONLY_SINGLETON_SUCCESSORS")?.unwrap_or(true);
        let compaction_prune_walk_interval_seconds =
            std::env::var("SOLAND_COMPACTION_PRUNE_WALK_INTERVAL_SECS")
                .ok()
                .and_then(|value| value.trim().parse::<u64>().ok())
                .unwrap_or(0);
        let compaction_prune_walk_per_realm_limit =
            std::env::var("SOLAND_COMPACTION_PRUNE_WALK_PER_REALM_LIMIT")
                .ok()
                .and_then(|value| value.trim().parse::<usize>().ok())
                .unwrap_or(50)
                .max(1);
        let seed_demo_data = env_bool("SOLAND_SEED_DEMO_DATA")?.unwrap_or(false);
        // Stream-F (Wave 2C) — erasure-receipt fanout window. Default 7
        // days per spec `realm-and-space.md` §2.5.2.
        let erasure_propagation_window_ms = std::env::var("SOLAND_ERASURE_PROPAGATION_WINDOW_MS")
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .unwrap_or(604_800_000);
        // G3.S9 — sovereign enclave toggle + outbound host allow-list.
        let sovereign_enclave_enabled = env_bool("SOLAND_SOVEREIGN_ENCLAVE")?.unwrap_or(false);
        let sovereign_enclave_allowed_outbound_hosts =
            std::env::var("SOLAND_SOVEREIGN_ENCLAVE_ALLOWED_OUTBOUND_HOSTS")
                .ok()
                .map(|v| {
                    v.split(',')
                        .map(|h| h.trim().to_owned())
                        .filter(|h| !h.is_empty())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
        let candidate_join_policy_enabled =
            env_bool("SOLAND_CANDIDATE_JOIN_POLICY")?.unwrap_or(false);
        // When the operator does not pin a trust domain, service bootstrap
        // derives it from the resolved runtime DID before AppState is built.
        let trust_domain = env_non_empty("SOLAND_TRUST_DOMAIN").unwrap_or_default();
        if !trust_domain.is_empty() {
            arkret_core::TypedTrustDomainId::new(trust_domain.clone()).map_err(|error| {
                anyhow::anyhow!("SOLAND_TRUST_DOMAIN must be ak:trust_domain:<scope>: {error}")
            })?;
        }
        let receive_policy_constraints = load_receive_policy_constraints()?;
        let log_format = LogFormat::from_env(development_mode);

        Ok(Self {
            bind,
            metrics_bind,
            public_base_url,
            first_provisioning,
            tls_cert_path,
            tls_key_path,
            database_url,
            object_storage,
            ice,
            livekit,
            cors_allow_origin,
            account_authority_url,
            account_authority_enrollment_did,
            oidc_client_id,
            development_mode,
            session_grant_introspection_url,
            session_grant_introspection_bearer,
            did_resolver_allow_methods,
            embedded_webvh_provider_enabled,
            embedded_webvh_registration_bearer,
            external_webvh_provider_url,
            external_webvh_registration_bearer,
            // `main.rs` flips this to true after a successful boot probe.
            external_webvh_provider_active: false,
            default_webvh_provider_id,
            jws_replay_window_seconds,
            jws_replay_window_per_family: Self::default_replay_overrides(),
            notary_signing_key_seed,
            key_store,
            federation_fanout_topology,
            federation_peers,
            federation_outbound_enabled,
            federation_replica_observer,
            admin_default_page_limit,
            admin_max_page_limit,
            admin_principal_dids,
            to_device_queue_capacity,
            push_bridge_cache_ttl_seconds,
            push_bridge_trusted_service_ids,
            resumable_upload_dir,
            resumable_upload_incomplete_ttl_seconds,
            seal_compaction_min_age_seconds,
            compaction_min_witnesses,
            compaction_preserve_genesis,
            compaction_prune_only_singleton_successors,
            compaction_prune_walk_interval_seconds,
            compaction_prune_walk_per_realm_limit,
            seed_demo_data,
            trust_domain,
            receive_policy_constraints,
            sovereign_enclave_enabled,
            sovereign_enclave_allowed_outbound_hosts,
            candidate_join_policy_enabled,
            erasure_propagation_window_ms,
            log_format,
        })
    }

    /// Maximum bytes Salvo will read from a request body before returning
    /// `413 Payload Too Large`. Env: `SOLAND_MAX_REQUEST_SIZE`, in bytes.
    pub fn max_request_size_bytes_from_env() -> usize {
        std::env::var("SOLAND_MAX_REQUEST_SIZE")
            .ok()
            .and_then(|value| value.trim().parse::<usize>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(DEFAULT_MAX_REQUEST_SIZE_BYTES)
    }

    /// Returns true when `actor` is configured as an admin principal in
    /// production mode via `SOLAND_ADMIN_PRINCIPAL_DIDS`.
    pub fn is_admin_principal(&self, actor: &str) -> bool {
        self.admin_principal_dids
            .iter()
            .any(|configured| configured == actor)
    }

    /// Derive the effective admin-API authentication posture from the
    /// current config. Returned values are stable strings safe to surface
    /// in `/health` and the soland-local `/_soland/describe`:
    ///
    ///   - `"development"` — `SOLAND_DEVELOPMENT_MODE=true`; any authenticated session may call
    ///     admin endpoints.
    ///   - `"did_allowlist"` — production mode, `SOLAND_ADMIN_PRINCIPAL_DIDS` is non-empty; admin
    ///     endpoints accept calls whose session actor appears in the allowlist.
    ///   - `"closed"` — production mode with neither admin allowlist nor introspection configured;
    ///     admin endpoints are effectively locked.
    pub fn admin_auth_mode(&self) -> &'static str {
        if self.development_mode {
            "development"
        } else if !self.admin_principal_dids.is_empty() {
            "did_allowlist"
        } else {
            "closed"
        }
    }

    /// String mirror of [`Self::development_mode`]: `"development"` or
    /// `"production"`. Exposed on `/health` and the soland-local
    /// `/_soland/describe` so operators can see at a glance whether proof
    /// verification is running in the relaxed dev-mode path.
    #[inline]
    pub fn proof_verifier_mode(&self) -> &'static str {
        if self.development_mode {
            "development"
        } else {
            "production"
        }
    }

    /// MAL-11 compaction policy assembled from the four env-driven config
    /// fields. Callers use this when evaluating prune candidates via
    /// [`arkret_state::CompactionPolicy::is_eligible`].
    pub fn compaction_policy(&self) -> arkret_state::CompactionPolicy {
        arkret_state::CompactionPolicy {
            min_seal_age_seconds: self.seal_compaction_min_age_seconds,
            min_compaction_witnesses: self.compaction_min_witnesses,
            preserve_genesis: self.compaction_preserve_genesis,
            prune_only_singleton_successors: self.compaction_prune_only_singleton_successors,
        }
    }

    #[inline]
    pub fn tls_enabled(&self) -> bool {
        self.tls_cert_path.is_some() && self.tls_key_path.is_some()
    }

    pub fn pq_hybrid_tls_probe_verified_from_value(value: Option<&str>) -> bool {
        let Some(value) = value else {
            return false;
        };
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "verified" | "x25519mlkem768" | "tls13+x25519mlkem768"
        )
    }

    pub fn pq_hybrid_tls_probe_verified(&self) -> bool {
        let value = env_non_empty(PQ_HYBRID_TLS_DEPLOYMENT_PROBE_ENV);
        Self::pq_hybrid_tls_probe_verified_from_value(value.as_deref())
    }

    pub fn pq_hybrid_tls_probe_configured(&self) -> bool {
        env_non_empty(PQ_HYBRID_TLS_DEPLOYMENT_PROBE_ENV).is_some()
    }

    pub fn pq_hybrid_tls_ready(&self) -> bool {
        self.development_mode || self.pq_hybrid_tls_probe_verified()
    }

    /// T8.3 — derive a non-sensitive production hardening snapshot from
    /// the live config. Values are environment-detected (no operator
    /// hand-holding required); `warnings[]` enumerates the failing
    /// checklist items so sodmin can render them inline.
    ///
    /// The returned struct deliberately keeps only booleans / coarse
    /// enums — no secret material, URLs, paths, or token tails — so it
    /// is safe to publish on the unauthenticated `/health` endpoint.
    pub fn hardening_status(&self) -> crate::wire::HardeningStatus {
        let development_mode = self.development_mode;
        let tls_enabled = self.tls_enabled();
        let pq_hybrid_tls_required_group =
            soland_application::protocol_artifacts::pq_hybrid_tls_required_group();
        let pq_hybrid_tls_probe_artifact =
            soland_application::protocol_artifacts::PQ_HYBRID_TLS_DEPLOYMENT_PROBE_ARTIFACT_REF;
        let pq_hybrid_tls_probe_verified = self.pq_hybrid_tls_probe_verified();
        // CSP is enforced upstream by the reverse proxy (Caddyfile /
        // nginx); we can't probe the live header from inside the app,
        // but a configured `cors_allow_origin` is a strong signal that
        // the operator has wired up the proxy layer for browser clients.
        let csp_header_configured = self.cors_allow_origin.is_some();
        // CORS is "strict" when it is either unset (no cross-origin
        // browser access) or set to a concrete origin list rather than
        // the `*` wildcard.
        let cors_strict = match self.cors_allow_origin.as_deref() {
            None => true,
            Some(value) => !value.trim().split(',').any(|origin| origin.trim() == "*"),
        };
        // A configured durable KeyStore or an explicit signing seed is the
        // minimum acceptable production posture.
        let secret_manager_in_use =
            self.notary_signing_key_seed.is_some() || self.key_store.is_durable();
        // Log redaction is structurally enforced by the tracing layer
        // (no PII fields are logged at INFO); we report true unless dev
        // mode flips us into the chatty path.
        let log_redaction_enabled = !development_mode;
        let admin_auth_mode = self.admin_auth_mode().to_owned();
        // The rate limiter middleware is unconditionally installed by
        // `router()` in every mode (only the per-class ceilings vary with the
        // deployment posture; see `crate::ratelimit::RateLimiterConfig::from_env`).
        let rate_limit_enabled = true;
        // Provider credential rotation: soland's only signing identity
        // is the notary key; rotation is manual today. The KeyStore
        // path is the closest thing to "scheduled" we ship.
        let provider_credential_rotation = if self.key_store.is_durable() {
            "scheduled".to_owned()
        } else if self.notary_signing_key_seed.is_some() {
            "manual".to_owned()
        } else {
            "none".to_owned()
        };

        let checks = [
            ("development_mode_disabled", !development_mode),
            ("tls_enabled", tls_enabled),
            ("pq_hybrid_tls_probe_verified", pq_hybrid_tls_probe_verified),
            ("csp_header_configured", csp_header_configured),
            ("cors_strict", cors_strict),
            ("secret_manager_in_use", secret_manager_in_use),
            ("log_redaction_enabled", log_redaction_enabled),
            (
                "admin_auth_mode_production",
                admin_auth_mode != "development",
            ),
            ("rate_limit_enabled", rate_limit_enabled),
            (
                "provider_credential_rotation",
                provider_credential_rotation != "none",
            ),
            (
                "demo_data_disabled",
                !self.seed_demo_data || development_mode,
            ),
        ];
        let checklist_max = checks.len() as u32;
        let mut checklist_score: u32 = 0;
        let mut warnings: Vec<String> = Vec::new();
        for (label, ok) in checks {
            if ok {
                checklist_score += 1;
            } else {
                warnings.push((*label).to_owned());
            }
        }

        // T4 — advisory (non-scored) ICE/TURN posture. A production
        // deployment still advertising the built-in placeholders has no
        // working relay (placeholder TURN host does not resolve) or leaks
        // candidate gathering to a third party (Google public STUN). These
        // do not lower the checklist score — they are operational hints —
        // but they surface on `/health` so operators notice unset RTC infra.
        if !development_mode {
            if self.ice.stun_urls.iter().any(|u| u == PLACEHOLDER_STUN_URL) {
                warnings.push("ice_stun_placeholder".to_owned());
            }
            if self
                .ice
                .turn_urls
                .iter()
                .any(|u| u.contains(PLACEHOLDER_TURN_HOST))
            {
                warnings.push("ice_turn_placeholder".to_owned());
            }
        }

        crate::wire::HardeningStatus {
            development_mode,
            tls_enabled,
            pq_hybrid_tls_required_group: pq_hybrid_tls_required_group.to_owned(),
            pq_hybrid_tls_probe_artifact: pq_hybrid_tls_probe_artifact.to_owned(),
            pq_hybrid_tls_probe_verified,
            csp_header_configured,
            cors_strict,
            secret_manager_in_use,
            log_redaction_enabled,
            admin_auth_mode,
            rate_limit_enabled,
            provider_credential_rotation,
            checklist_score,
            checklist_max,
            warnings,
        }
    }
}

fn load_object_storage_config() -> anyhow::Result<ObjectStorageConfig> {
    let backend = env_non_empty("SOLAND_OBJECT_STORAGE_BACKEND")
        .unwrap_or_else(|| "local".to_owned())
        .to_ascii_lowercase();
    let prefix = normalized_storage_prefix(env_non_empty("SOLAND_OBJECT_STORAGE_PREFIX"));
    match backend.as_str() {
        "local" | "fs" | "filesystem" => {
            let root = env_non_empty("SOLAND_OBJECT_STORAGE_LOCAL_ROOT")
                .map(PathBuf::from)
                .unwrap_or_else(|| std::env::temp_dir().join("soland-objects"));
            Ok(ObjectStorageConfig::Local { root, prefix })
        }
        "s3" | "s3-compatible" | "s3_compatible" => {
            let bucket = required_env("SOLAND_OBJECT_STORAGE_S3_BUCKET")?;
            let region = env_non_empty("SOLAND_OBJECT_STORAGE_S3_REGION")
                .unwrap_or_else(|| "us-east-1".to_owned());
            let access_key_id = env_non_empty("SOLAND_OBJECT_STORAGE_S3_ACCESS_KEY_ID");
            let secret_access_key = env_non_empty("SOLAND_OBJECT_STORAGE_S3_SECRET_ACCESS_KEY");
            if access_key_id.is_some() != secret_access_key.is_some() {
                anyhow::bail!(
                    "SOLAND_OBJECT_STORAGE_S3_ACCESS_KEY_ID and SOLAND_OBJECT_STORAGE_S3_SECRET_ACCESS_KEY must be set together"
                );
            }
            Ok(ObjectStorageConfig::S3Compatible {
                bucket,
                region,
                endpoint: env_non_empty("SOLAND_OBJECT_STORAGE_S3_ENDPOINT"),
                access_key_id,
                secret_access_key,
                session_token: env_non_empty("SOLAND_OBJECT_STORAGE_S3_SESSION_TOKEN"),
                prefix,
                force_path_style: env_bool("SOLAND_OBJECT_STORAGE_S3_FORCE_PATH_STYLE")?
                    .unwrap_or(true),
                allow_http: env_bool("SOLAND_OBJECT_STORAGE_S3_ALLOW_HTTP")?.unwrap_or(false),
                skip_signature: env_bool("SOLAND_OBJECT_STORAGE_S3_SKIP_SIGNATURE")?
                    .unwrap_or(false),
            })
        }
        other => anyhow::bail!(
            "SOLAND_OBJECT_STORAGE_BACKEND must be local or s3-compatible, got {other}"
        ),
    }
}

/// Load ICE/STUN/TURN configuration from `SOLAND_ICE_*` / `SOLAND_TURN_*`
/// env vars. Each field falls back to the corresponding
/// [`IceServersConfig::default`] value when its env var is absent or empty,
/// preserving the historical hardcoded behavior.
fn load_ice_servers_config() -> anyhow::Result<IceServersConfig> {
    let defaults = IceServersConfig::default();
    let parse_url_list = |name: &str, fallback: Vec<String>| -> Vec<String> {
        match env_non_empty(name) {
            Some(raw) => {
                let parsed = raw
                    .split(',')
                    .map(|part| part.trim().to_owned())
                    .filter(|part| !part.is_empty())
                    .collect::<Vec<_>>();
                if parsed.is_empty() { fallback } else { parsed }
            }
            None => fallback,
        }
    };
    let stun_urls = parse_url_list("SOLAND_ICE_STUN_URLS", defaults.stun_urls);
    let turn_urls = parse_url_list("SOLAND_TURN_URLS", defaults.turn_urls);
    let ttl_seconds = env_non_empty("SOLAND_ICE_TTL_SECONDS")
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(defaults.ttl_seconds);
    let refresh_lead_seconds = env_non_empty("SOLAND_ICE_REFRESH_LEAD_SECONDS")
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(defaults.refresh_lead_seconds);
    let turn_secret_rotation_window_seconds =
        env_non_empty("SOLAND_TURN_SECRET_ROTATION_WINDOW_SECS")
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(defaults.turn_secret_rotation_window_seconds);
    let turn_shared_secret = env_non_empty_or_file("SOLAND_TURN_SHARED_SECRET")?;
    Ok(IceServersConfig {
        stun_urls,
        turn_urls,
        ttl_seconds,
        refresh_lead_seconds,
        turn_secret_rotation_window_seconds,
        turn_shared_secret,
    })
}

fn normalized_storage_prefix(prefix: Option<String>) -> String {
    prefix
        .map(|value| {
            value
                .trim()
                .trim_matches('/')
                .split('/')
                .filter(|part| !part.is_empty())
                .collect::<Vec<_>>()
                .join("/")
        })
        .unwrap_or_default()
}

/// Load the NotaryWorker signing seed from
/// `SOLAND_NOTARY_SIGNING_KEY` (base64-standard encoded 32 bytes).
/// Returns `Ok(None)` when the env var is absent or empty (the
/// NotaryWorker then mints an ephemeral key with a sticky-warn).
/// Returns `Err(_)` when the env var is set but malformed — fail-fast at
/// startup rather than silently downgrading to ephemeral.
fn load_notary_signing_key_seed() -> anyhow::Result<Option<[u8; 32]>> {
    let raw = match std::env::var("SOLAND_NOTARY_SIGNING_KEY") {
        Ok(value) => value.trim().to_owned(),
        Err(_) => return Ok(None),
    };
    if raw.is_empty() {
        return Ok(None);
    }
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(raw.as_bytes())
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(raw.as_bytes()))
        .map_err(|e| {
            anyhow::anyhow!(
                "SOLAND_NOTARY_SIGNING_KEY must be base64 (standard or url-safe-no-pad): {e}"
            )
        })?;
    if bytes.len() != 32 {
        anyhow::bail!(
            "SOLAND_NOTARY_SIGNING_KEY must decode to exactly 32 bytes (got {})",
            bytes.len()
        );
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    Ok(Some(seed))
}

/// Round R2/R3 (T08) — derive a deployment-bound trust domain id.
///
/// Order of resolution:
/// 1. `SOLAND_TRUST_DOMAIN` env var if set (must validate as `ak:trust_domain:<scope>` per SDK
///    [`arkret_core::TypedTrustDomainId`]).
/// 2. Synthesised from the configured `service_id` — strip the DID method prefix and lowercase the
///    remainder, then prefix with `ak:trust_domain:`.
pub fn derive_trust_domain(service_id: &str) -> anyhow::Result<String> {
    if let Some(value) = env_non_empty("SOLAND_TRUST_DOMAIN") {
        // Validate via SDK typed id — rejects bad shape at boot.
        arkret_core::TypedTrustDomainId::new(value.clone()).map_err(|e| {
            anyhow::anyhow!("SOLAND_TRUST_DOMAIN must be ak:trust_domain:<scope>: {e}")
        })?;
        return Ok(value);
    }
    let host = did_host_from_service_id(service_id)
        .or_else(|| service_id.strip_prefix("did:key:").map(str::to_owned))
        .unwrap_or_else(|| service_id.to_owned());
    // Normalise to the SDK scope grammar: lowercase, keep
    // [a-z0-9.\-_:].
    let scope: String = host
        .to_ascii_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'))
        .collect();
    let scope = if scope.is_empty() {
        "local".to_owned()
    } else {
        scope
    };
    let candidate = format!("ak:trust_domain:{scope}");
    // Final safety check.
    arkret_core::TypedTrustDomainId::new(candidate.clone()).map_err(|e| {
        anyhow::anyhow!(
            "derived trust_domain from service_id {service_id:?} failed validation: {e}"
        )
    })?;
    Ok(candidate)
}

pub(crate) fn did_host_from_service_id(service_id: &str) -> Option<String> {
    let host = if let Some(rest) = service_id.strip_prefix("did:web:") {
        rest.split(':').next()?
    } else {
        let rest = service_id.strip_prefix("did:webvh:")?;
        let mut parts = rest.split(':');
        let scid = parts.next()?;
        let host = parts.next()?;
        if scid.is_empty() {
            return None;
        }
        host
    };
    let host = host
        .split("%3A")
        .next()
        .unwrap_or(host)
        .split("%3a")
        .next()
        .unwrap_or(host)
        .trim_end_matches('.');
    // Hosts are case-insensitive; return the canonical lowercase form. This is
    // the single canonical implementation — `federation::signature` delegates
    // here rather than keeping a second copy that had drifted on casing.
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

fn load_receive_policy_constraints() -> anyhow::Result<Option<arkret_core::ReceivePolicyConstraints>>
{
    let applies_to = env_csv_cap("SOLAND_RECEIVE_POLICY_APPLIES_TO")
        .map(|values| {
            values
                .into_iter()
                .map(|value| match value.as_str() {
                    "invite_delivery" => Ok(arkret_core::ReceivePolicySurface::InviteDelivery),
                    "contact_request" => Ok(arkret_core::ReceivePolicySurface::ContactRequest),
                    other => anyhow::bail!(
                        "SOLAND_RECEIVE_POLICY_APPLIES_TO contains unsupported surface {other}"
                    ),
                })
                .collect::<anyhow::Result<Vec<_>>>()
        })
        .transpose()?;
    let permitted_introduction_kinds =
        env_csv_cap("SOLAND_RECEIVE_POLICY_PERMITTED_INTRODUCTION_KINDS");
    let forbidden_introduction_kinds =
        env_csv_cap("SOLAND_RECEIVE_POLICY_FORBIDDEN_INTRODUCTION_KINDS").unwrap_or_default();
    let handle_claim_max_behavior =
        env_receive_action("SOLAND_RECEIVE_POLICY_HANDLE_CLAIM_MAX_BEHAVIOR")?;
    let explicit_address_max_behavior =
        env_receive_action("SOLAND_RECEIVE_POLICY_EXPLICIT_ADDRESS_MAX_BEHAVIOR")?;
    let unknown_invites_max_behavior =
        env_unknown_action("SOLAND_RECEIVE_POLICY_UNKNOWN_INVITES_MAX_BEHAVIOR")?;
    let allowed_handle_domains =
        env_csv_cap("SOLAND_RECEIVE_POLICY_ALLOWED_HANDLE_DOMAINS").map(|domains| {
            domains
                .into_iter()
                .map(|domain| domain.to_ascii_lowercase())
                .collect()
        });
    let trusted_handle_issuers = env_did_csv_cap("SOLAND_RECEIVE_POLICY_TRUSTED_HANDLE_ISSUERS")?;
    let trusted_directory_services =
        env_did_csv_cap("SOLAND_RECEIVE_POLICY_TRUSTED_DIRECTORY_SERVICES")?;
    let trusted_principal_services =
        env_did_csv_cap("SOLAND_RECEIVE_POLICY_TRUSTED_PRINCIPAL_SERVICES")?;
    let blocked_principal_services =
        env_did_csv_cap("SOLAND_RECEIVE_POLICY_BLOCKED_PRINCIPAL_SERVICES")?;
    let accepted_subject_did_methods =
        env_csv_cap("SOLAND_RECEIVE_POLICY_ACCEPTED_SUBJECT_DID_METHODS");

    let has_any_constraint = applies_to.is_some()
        || permitted_introduction_kinds.is_some()
        || !forbidden_introduction_kinds.is_empty()
        || handle_claim_max_behavior.is_some()
        || explicit_address_max_behavior.is_some()
        || unknown_invites_max_behavior.is_some()
        || allowed_handle_domains.is_some()
        || trusted_handle_issuers.is_some()
        || trusted_directory_services.is_some()
        || trusted_principal_services.is_some()
        || blocked_principal_services.is_some()
        || accepted_subject_did_methods.is_some();
    if !has_any_constraint {
        return Ok(None);
    }

    Ok(Some(arkret_core::ReceivePolicyConstraints {
        policy_version: Some("env".to_owned()),
        applies_to,
        permitted_introduction_kinds,
        forbidden_introduction_kinds,
        handle_claim_max_behavior,
        explicit_address_max_behavior,
        unknown_invites_max_behavior,
        allowed_handle_domains,
        trusted_handle_issuers,
        trusted_directory_services,
        trusted_principal_services,
        blocked_principal_services,
        accepted_subject_did_methods,
    }))
}

fn env_receive_action(name: &str) -> anyhow::Result<Option<arkret_core::InviteReceiveAction>> {
    let Some(value) = env_non_empty(name) else {
        return Ok(None);
    };
    match value.as_str() {
        "drop" => Ok(Some(arkret_core::InviteReceiveAction::Drop)),
        "quarantine" => Ok(Some(arkret_core::InviteReceiveAction::Quarantine)),
        "notify" => Ok(Some(arkret_core::InviteReceiveAction::Notify)),
        other => anyhow::bail!("{name} must be drop, quarantine, or notify; got {other}"),
    }
}

fn env_unknown_action(name: &str) -> anyhow::Result<Option<arkret_core::UnknownInviteAction>> {
    let Some(value) = env_non_empty(name) else {
        return Ok(None);
    };
    match value.as_str() {
        "drop" => Ok(Some(arkret_core::UnknownInviteAction::Drop)),
        "quarantine" => Ok(Some(arkret_core::UnknownInviteAction::Quarantine)),
        other => anyhow::bail!("{name} must be drop or quarantine; got {other}"),
    }
}

fn env_csv_cap(name: &str) -> Option<Vec<String>> {
    let raw = std::env::var(name).ok()?;
    Some(
        raw.split(',')
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .collect(),
    )
}

fn env_did_csv_cap(name: &str) -> anyhow::Result<Option<Vec<arkret_core::Did>>> {
    let Some(values) = env_csv_cap(name) else {
        return Ok(None);
    };
    values
        .into_iter()
        .map(|value| {
            arkret_core::Did::new(value.clone())
                .map_err(|error| anyhow::anyhow!("{name} contains invalid DID `{value}`: {error}"))
        })
        .collect::<anyhow::Result<Vec<_>>>()
        .map(Some)
}

fn env_csv(name: &str) -> Option<Vec<String>> {
    let values: Vec<String> = std::env::var(name)
        .ok()?
        .split(',')
        .map(|value| value.trim().trim_start_matches("did:").to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .collect();
    if values.is_empty() {
        None
    } else {
        Some(values)
    }
}

fn default_did_resolver_allow_methods() -> Vec<String> {
    // did:webvh-only red line: `web` is intentionally absent from the default
    // resolver allow-list. Deployments that must interoperate with bare
    // did:web peers can opt in explicitly via SOLAND_DID_RESOLVER_ALLOW_METHODS.
    vec!["webvh".to_owned(), "key".to_owned(), "uuid".to_owned()]
}

fn env_non_empty(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

/// Resolve a secret-like value from `$NAME` OR from a file at `$NAME_FILE`.
///
/// Lets operators mount a token via Kubernetes / Docker / systemd secrets
/// instead of inlining it in env. Empty / whitespace-only files are treated
/// as unset, mirroring [`env_non_empty`].
///
/// # Errors
///
/// - `$NAME_FILE` is set but the path cannot be read.
/// - Both `$NAME` and `$NAME_FILE` are set to different non-empty values.
fn env_non_empty_or_file(name: &str) -> anyhow::Result<Option<String>> {
    let from_env = env_non_empty(name);
    let file_name = format!("{name}_FILE");
    let file_value = match env_non_empty(&file_name) {
        Some(path) => {
            let raw = std::fs::read_to_string(&path).map_err(|error| {
                anyhow::anyhow!(
                    "{file_name} points to {path:?} but the file could not be read: {error}"
                )
            })?;
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_owned())
            }
        }
        None => None,
    };
    match (from_env, file_value) {
        (None, None) => Ok(None),
        (Some(value), None) | (None, Some(value)) => Ok(Some(value)),
        (Some(env), Some(file)) if env == file => Ok(Some(env)),
        (Some(_), Some(_)) => {
            anyhow::bail!("{name} and {file_name} are both set to different values; pick one")
        }
    }
}

fn required_env(name: &str) -> anyhow::Result<String> {
    env_non_empty(name).ok_or_else(|| anyhow::anyhow!("{name} is required"))
}

fn env_bool(name: &str) -> anyhow::Result<Option<bool>> {
    let Some(value) = env_non_empty(name) else {
        return Ok(None);
    };
    match value.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(Some(true)),
        "0" | "false" | "no" | "off" => Ok(Some(false)),
        _ => anyhow::bail!("{name} must be true or false"),
    }
}

fn arg_value(name: &str) -> Option<String> {
    let mut args = std::env::args();
    while let Some(arg) = args.next() {
        if arg == name {
            return args.next();
        }
    }
    None
}

#[cfg(test)]
#[allow(unsafe_code)]
mod tests {
    use super::*;

    #[test]
    fn key_store_config_selects_backends_and_rejects_legacy_switch() {
        use base64::Engine as _;

        let backend = ScopedEnv::new("SOLAND_KEYSTORE_BACKEND");
        let path = ScopedEnv::new("SOLAND_KEYSTORE_PATH");
        let master_key = ScopedEnv::new("SOLAND_KEYSTORE_MASTER_KEY");
        let legacy = ScopedEnv::new("SOLAND_USE_KEYSTORE");

        assert!(matches!(
            KeyStoreConfig::from_env().unwrap(),
            KeyStoreConfig::Disabled
        ));

        backend.set_env("platform");
        assert!(matches!(
            KeyStoreConfig::from_env().unwrap(),
            KeyStoreConfig::Platform
        ));

        backend.set_env("encrypted_file");
        path.set_env("soland-test-keystore.v1");
        let encoded = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        master_key.set_env(&encoded);
        let encrypted = KeyStoreConfig::from_env().unwrap();
        assert_eq!(encrypted.backend_name(), Some("encrypted_file"));
        assert!(!format!("{encrypted:?}").contains(&encoded));

        backend.clear();
        path.clear();
        master_key.clear();
        legacy.set_env("true");
        let error = KeyStoreConfig::from_env().expect_err("legacy switch must fail");
        assert!(error.to_string().contains("was removed"));
    }

    #[test]
    fn persistent_database_requires_durable_key_store() {
        let error =
            validate_persistence_key_store(Some("postgres://example"), &KeyStoreConfig::Disabled)
                .expect_err("persistent database with ephemeral keys must fail");
        assert!(error.to_string().contains("DATABASE_URL requires"));
        validate_persistence_key_store(Some("postgres://example"), &KeyStoreConfig::Platform)
            .unwrap();
        validate_persistence_key_store(None, &KeyStoreConfig::Disabled).unwrap();
    }

    #[test]
    fn default_did_resolver_allow_methods_webvh_only_no_bare_web() {
        // did:webvh-only red line: bare `web` must never be in the default
        // resolver allow-list; it is opt-in via env override only.
        let methods = default_did_resolver_allow_methods();
        assert_eq!(methods, vec!["webvh", "key", "uuid"]);
        assert!(!methods.iter().any(|m| m == "web"));
    }

    #[test]
    fn trust_domain_derives_webvh_host_not_scid() {
        let _env = ScopedEnv::new("SOLAND_TRUST_DOMAIN");
        let trust_domain = derive_trust_domain(
            "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:local.host:webvh:service",
        )
        .unwrap();
        assert_eq!(trust_domain, "ak:trust_domain:local.host");
    }

    #[test]
    fn ice_servers_defaults_match_historical_hardcoded_values() {
        // These defaults must keep the pre-externalization wire behavior so
        // deployments that do not set `SOLAND_ICE_*` / `SOLAND_TURN_*` see no
        // change in their issued ICE configs.
        let ice = IceServersConfig::default();
        assert_eq!(ice.stun_urls, vec!["stun:stun.l.google.com:19302"]);
        assert_eq!(
            ice.turn_urls,
            vec!["turn:turn.soland.local:3478?transport=udp"]
        );
        assert_eq!(ice.ttl_seconds, 300);
        assert_eq!(ice.refresh_lead_seconds, 75);
        assert_eq!(ice.turn_secret_rotation_window_seconds, 86_400);
        assert!(ice.turn_shared_secret.is_none());
    }

    #[test]
    fn load_ice_servers_config_parses_env_overrides() {
        // All SOLAND_ICE_* / SOLAND_TURN_* vars are exercised in a single
        // test so the fixed (non-unique) env-var names cannot race against a
        // sibling test reading the same keys.
        let stun = ScopedEnv::new("SOLAND_ICE_STUN_URLS");
        let turn = ScopedEnv::new("SOLAND_TURN_URLS");
        let ttl = ScopedEnv::new("SOLAND_ICE_TTL_SECONDS");
        let lead = ScopedEnv::new("SOLAND_ICE_REFRESH_LEAD_SECONDS");
        let rotation = ScopedEnv::new("SOLAND_TURN_SECRET_ROTATION_WINDOW_SECS");
        stun.set_env("stun:stun.example:3478 , stun:stun2.example:3478");
        turn.set_env("turn:turn.example:3478?transport=udp");
        ttl.set_env("120");
        lead.set_env("30");
        rotation.set_env("3600");

        let ice = load_ice_servers_config().expect("load ice config");
        assert_eq!(
            ice.stun_urls,
            vec!["stun:stun.example:3478", "stun:stun2.example:3478"]
        );
        assert_eq!(ice.turn_urls, vec!["turn:turn.example:3478?transport=udp"]);
        assert_eq!(ice.ttl_seconds, 120);
        assert_eq!(ice.refresh_lead_seconds, 30);
        assert_eq!(ice.turn_secret_rotation_window_seconds, 3600);

        // A non-positive TTL is rejected and falls back to the default.
        ttl.set_env("0");
        let ice = load_ice_servers_config().expect("load ice config");
        assert_eq!(ice.ttl_seconds, 300);
    }

    /// Guard that scopes env-var mutation to a single test. The Rust
    /// 2024 edition marks `set_var`/`remove_var` `unsafe`; this wrapper
    /// localises the unsafe block and restores env on drop so tests
    /// running in parallel against unique names never leak state.
    struct ScopedEnv {
        name: String,
        file_name: String,
    }

    impl ScopedEnv {
        fn new(name: &str) -> Self {
            let guard = Self {
                name: name.to_owned(),
                file_name: format!("{name}_FILE"),
            };
            guard.clear();
            guard
        }

        fn set_env(&self, value: &str) {
            // SAFETY: scoped to a unique env var per test; clear() runs on drop.
            unsafe { std::env::set_var(&self.name, value) };
        }

        fn set_file(&self, value: &str) {
            // SAFETY: scoped to a unique env var per test; clear() runs on drop.
            unsafe { std::env::set_var(&self.file_name, value) };
        }

        fn clear(&self) {
            // SAFETY: scoped to env vars this guard owns.
            unsafe {
                std::env::remove_var(&self.name);
                std::env::remove_var(&self.file_name);
            }
        }
    }

    impl Drop for ScopedEnv {
        fn drop(&mut self) {
            self.clear();
        }
    }

    fn write_secret_file(suffix: &str, contents: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "soland-config-test-{}-{suffix}",
            std::process::id()
        ));
        std::fs::write(&path, contents).expect("write secret file");
        path
    }

    #[test]
    fn env_only_returns_value() {
        let env = ScopedEnv::new("SOLAND_TEST_BEARER_ENV_ONLY");
        env.set_env("from-env");
        assert_eq!(
            env_non_empty_or_file(&env.name).unwrap(),
            Some("from-env".to_owned())
        );
    }

    #[test]
    fn file_only_returns_value() {
        let env = ScopedEnv::new("SOLAND_TEST_BEARER_FILE_ONLY");
        let path = write_secret_file("file-only", "from-file\n");
        env.set_file(path.to_str().unwrap());
        assert_eq!(
            env_non_empty_or_file(&env.name).unwrap(),
            Some("from-file".to_owned())
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn neither_set_returns_none() {
        let env = ScopedEnv::new("SOLAND_TEST_BEARER_NEITHER");
        assert!(env_non_empty_or_file(&env.name).unwrap().is_none());
    }

    #[test]
    fn both_set_to_same_value_is_ok() {
        let env = ScopedEnv::new("SOLAND_TEST_BEARER_BOTH_SAME");
        env.set_env("same-tok");
        let path = write_secret_file("both-same", "same-tok");
        env.set_file(path.to_str().unwrap());
        assert_eq!(
            env_non_empty_or_file(&env.name).unwrap(),
            Some("same-tok".to_owned())
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn both_set_to_different_values_errors() {
        let env = ScopedEnv::new("SOLAND_TEST_BEARER_BOTH_DIFF");
        env.set_env("env-tok");
        let path = write_secret_file("both-diff", "file-tok");
        env.set_file(path.to_str().unwrap());
        let error = env_non_empty_or_file(&env.name).expect_err("must error");
        assert!(
            error
                .to_string()
                .contains("are both set to different values"),
            "unexpected error: {error}"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn file_pointing_to_missing_path_errors() {
        let env = ScopedEnv::new("SOLAND_TEST_BEARER_MISSING_FILE");
        env.set_file("/definitely/does/not/exist-soland-test");
        let error = env_non_empty_or_file(&env.name).expect_err("must error");
        assert!(
            error.to_string().contains("could not be read"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn whitespace_file_is_treated_as_unset() {
        let env = ScopedEnv::new("SOLAND_TEST_BEARER_WS_FILE");
        let path = write_secret_file("ws-file", "   \n\t  \n");
        env.set_file(path.to_str().unwrap());
        assert!(env_non_empty_or_file(&env.name).unwrap().is_none());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn pq_hybrid_tls_probe_parser_accepts_only_artifact_success_values() {
        assert!(AppConfig::pq_hybrid_tls_probe_verified_from_value(Some(
            "verified"
        )));
        assert!(AppConfig::pq_hybrid_tls_probe_verified_from_value(Some(
            "X25519MLKEM768"
        )));
        assert!(AppConfig::pq_hybrid_tls_probe_verified_from_value(Some(
            "tls13+x25519mlkem768"
        )));
        assert!(!AppConfig::pq_hybrid_tls_probe_verified_from_value(Some(
            "classical-x25519"
        )));
        assert!(!AppConfig::pq_hybrid_tls_probe_verified_from_value(None));
    }
}
