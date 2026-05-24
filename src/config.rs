use std::net::SocketAddr;
use std::path::PathBuf;

pub const DEFAULT_MAX_REQUEST_SIZE_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug)]
pub struct AppConfig {
    pub bind: SocketAddr,
    pub metrics_bind: SocketAddr,
    pub public_base_url: String,
    pub service_did: String,
    /// Optional TLS certificate PEM path. When both this and
    /// [`tls_key_path`] are configured, soland starts an HTTPS listener using
    /// Salvo's rustls integration instead of plain TCP.
    pub tls_cert_path: Option<PathBuf>,
    /// Optional TLS private-key PEM path paired with [`tls_cert_path`].
    pub tls_key_path: Option<PathBuf>,
    pub database_url: Option<String>,
    pub object_storage: ObjectStorageConfig,
    pub cors_allow_origin: Option<String>,
    /// Public Auth / Account Server base URL advertised to browser clients in
    /// `/api/v1/server/describe.auth_metadata`. Registration, password
    /// recovery, passkey, OIDC, and email verification live there; soland only
    /// consumes the resulting OAuth/session grants and may expose DID provider
    /// primitives for trusted server-to-server calls.
    pub auth_server_url: Option<String>,
    pub development_mode: bool,
    /// Matrix/Palpo-style OAuth 2.0 introspection endpoint. When configured,
    /// soland accepts the caller's `Authorization: Bearer <coauth access token>`
    /// directly and verifies it by POSTing to this endpoint with
    /// [`oauth_introspection_bearer`].
    pub oauth_introspection_url: Option<String>,
    /// Shared service bearer sent to [`oauth_introspection_url`] as
    /// `Authorization: Bearer ...`. This mirrors the Matrix Authentication
    /// Service / homeserver shared-secret model and is never exposed to
    /// browsers or clients.
    pub oauth_introspection_bearer: Option<String>,
    pub session_grant_introspection_url: Option<String>,
    pub session_grant_introspection_bearer: Option<String>,
    pub did_resolver_allow_methods: Vec<String>,
    /// Enable soland's built-in `did:webvh` provider. This is intended for
    /// ordinary self-hosted deployments and tests: coauth can discover it via
    /// `/api/v1/identity/describe`, register a user DID through soland, then
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
    /// Runtime liveness for the external provider. `true` only when the
    /// external provider's `/describe` probe succeeds at boot.
    pub external_webvh_provider_active: bool,
    /// Provider id coauth should preselect. When unset, soland chooses
    /// `soland.embedded` if the embedded provider is enabled, otherwise the
    /// first configured external provider.
    pub default_webvh_provider_id: Option<String>,
    /// JWS replay protection window in seconds.
    /// Move and Anchor signatures whose signed `hlc` is older than
    /// `now - replay_window_seconds` OR newer than `now +
    /// replay_window_seconds` are rejected.
    ///
    /// Default 300s = 5 min — matches the Contrix spec recommendation in
    /// `signatures-and-replay.md`. Set to `0` to disable (dev / tests
    /// using fixed-time fixtures rely on this; production deployments
    /// MUST keep this > 0).
    pub jws_replay_window_seconds: u64,
    /// Per-cell-family replay-window overrides.
    /// Some cell families have different freshness requirements than the
    /// global default — e.g. `cx.component.anchorer.v1` (Space-wide
    /// authority cell) needs a much tighter window than chat messages.
    /// When a Move's `effects[]` touch any cell whose family appears in
    /// this map, the **minimum** override across touched families wins
    /// (most-restrictive). Falls back to `jws_replay_window_seconds` for
    /// families without an override.
    ///
    /// Production default (built by [`AppConfig::default_replay_overrides`]):
    /// - `cx.component.anchorer.v1` → 60s (very fresh — Space-wide pause risk)
    /// - `cx.component.mls.epoch.v1` → 60s (E2EE fork risk)
    /// - `cx.component.consent.grant.v1` → 120s (capability-equivalent)
    /// - `cx.component.capability.grant.v1` → 120s
    /// - `cx.component.capability.delegate.v1` → 120s
    /// - `cx.component.capability.derived.v1` → 120s
    pub jws_replay_window_per_family: std::collections::BTreeMap<&'static str, u64>,
    /// Base64-encoded 32-byte ed25519 seed for the AnchorerWorker
    /// signing identity (env `SOLAND_ANCHORER_SIGNING_KEY`). When `Some(_)`
    /// the worker uses a deterministic ed25519-dalek signing key derived
    /// from this seed; when `None` the worker boots with an in-process
    /// random ephemeral key and a sticky-warn log line on every signing
    /// pass, matching the [`AnchorerSigningKeyOrigin::Ephemeral`] branch.
    ///
    /// Loading is identical to coauth's session-grant signing-key pattern
    /// — the env var holds the raw seed, base64-standard-padded; bad shape
    /// fails fast at startup with a clear error.
    pub anchorer_signing_key_seed: Option<[u8; 32]>,
    /// Per-deployment Ed25519 seed used by the reference agent runtime
    /// to sign `audit_binding` blocks on `cx.agent.protocol_session.result`
    /// events. When `None` (default), the bridge falls back to
    /// `REFERENCE_AGENT_AUDIT_ED25519_SEED` — fine for dev / reference
    /// deployments but provides no real authentication because every
    /// other soland deployment can recompute the same signature.
    ///
    /// Env var `SOLAND_AGENT_AUDIT_BINDING_SIGNING_SEED` accepts a
    /// 32-byte seed base64-standard-padded; bad shape fails fast at
    /// startup. Production deployments SHOULD set this so the agent
    /// service's verifying key is uniquely bound to the runtime.
    pub agent_audit_binding_signing_seed: Option<[u8; 32]>,
    /// When true, the AnchorerWorker loads its signing seed
    /// from the SDK platform `KeyStore` (`platform_default_keystore("soland.<service_did>")`)
    /// at boot and stores rotated keys back into the same KeyStore. When
    /// false (default), only `anchorer_signing_key_seed` (env-loaded) is
    /// honored. The KeyStore key id is `contrix:signer:soland-anchorer:<service_did>`.
    ///
    /// Behavior when `use_keystore=true`:
    /// - First boot: try `KeyStore::load(...)`; on `not_found` fall back to
    ///   `anchorer_signing_key_seed`; if that's also absent, mint a fresh seed and persist it via
    ///   `KeyStore::store(...)` (one-shot init).
    /// - `rotate-signing-key` endpoint: mint, persist via KeyStore, hot-swap.
    ///
    /// Behavior when `use_keystore=false`: only the env-loaded seed is honored.
    pub use_keystore: bool,
    /// Federation routing policy. The on-the-wire
    /// shape is identical for both variants (Move broadcast push / Anchor
    /// pull-push under `/api/v1/federation/{push-operations,anchors,...}`);
    /// the policy only changes which set of peer endpoints we talk to.
    ///
    /// - [`FederationPolicy::Mesh`] — broadcast each accepted Move to every known peer
    ///   (gossip-like). Anchors are replicated via pull-push when peer pressure spikes. Default.
    /// - [`FederationPolicy::Hub`] — push only to a single configured upstream hub; rely on the
    ///   hub for outbound dissemination.
    pub federation_policy: FederationPolicy,
    /// Peer DIDs the federation outbound layer
    /// considers as broadcast targets (mesh) or hub upstream (hub). Empty
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
    /// Default page size for `GET /api/v1/admin/cells` and the rest of
    /// the admin paginated read surfaces when the caller omits `limit`.
    /// Env: `SOLAND_ADMIN_PAGE_LIMIT` (default `100`).
    pub admin_default_page_limit: usize,
    /// Hard cap on `limit` query for the admin paginated read surfaces;
    /// requests asking for a larger page are clamped down. Defends
    /// against a misbehaving client exhausting in-memory projection state.
    /// Env: `SOLAND_ADMIN_MAX_PAGE_LIMIT` (default `1000`).
    pub admin_max_page_limit: usize,
    /// Principal DIDs allowed to call `GET /api/v1/admin/{resource}` and the
    /// other production-gated admin read surfaces when `development_mode` is
    /// false. Empty (default) keeps the previous "dev-mode only" posture for
    /// these endpoints. Env: `SOLAND_ADMIN_PRINCIPAL_DIDS` (comma-separated).
    pub admin_principal_dids: Vec<String>,
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
    /// Env: `SOLAND_PUSH_BRIDGE_TRUSTED_SERVICE_DIDS` (comma-separated).
    pub push_bridge_trusted_service_dids: Vec<String>,
    /// MAL-11 compaction: minimum age (seconds) before an Anchor is
    /// prune-eligible. Younger Anchors must not be pruned even when a
    /// compaction Anchor has witnessed them — gives slow federation peers
    /// time to backfill before history is dropped.
    /// Env: `SOLAND_COMPACTION_MIN_ANCHOR_AGE_SECS` (default 604_800 = 7 days).
    pub compaction_min_anchor_age_seconds: u64,
    /// MAL-11 compaction: minimum number of compaction Anchors between
    /// the prune candidate and the current leaf set.
    /// Env: `SOLAND_COMPACTION_MIN_WITNESSES` (default 1).
    pub compaction_min_witnesses: u32,
    /// MAL-11 compaction: refuse to prune the genesis Anchor when true.
    /// Env: `SOLAND_COMPACTION_PRESERVE_GENESIS` (default true).
    pub compaction_preserve_genesis: bool,
    /// MAL-11 compaction: refuse to prune fork-point Anchors (more than
    /// one direct successor) when true. Keeps the prune walk
    /// conservative by default.
    /// Env: `SOLAND_COMPACTION_PRUNE_ONLY_SINGLETON_SUCCESSORS` (default true).
    pub compaction_prune_only_singleton_successors: bool,
    /// MAL-11 compaction prune walk: interval between background prune
    /// passes, in seconds. Zero (or unset) disables the worker entirely —
    /// MAL-11 prune then runs only via the explicit
    /// `POST /api/admin/v1/spaces/{space_id}/anchor-dag/prune?anchor_id=...`
    /// endpoint. When enabled, the worker walks every live Space's
    /// anchor DAG, evaluates each candidate against
    /// [`compaction_policy`], and prunes eligible Anchors up to
    /// `compaction_prune_walk_per_space_limit` per Space per pass.
    /// Env: `SOLAND_COMPACTION_PRUNE_WALK_INTERVAL_SECS` (default 0 = disabled).
    pub compaction_prune_walk_interval_seconds: u64,
    /// MAL-11 compaction prune walk: maximum number of prunes the worker
    /// will perform per Space per pass. Bounds I/O against very large
    /// DAGs; further candidates are picked up on subsequent ticks.
    /// Env: `SOLAND_COMPACTION_PRUNE_WALK_PER_SPACE_LIMIT` (default 50).
    pub compaction_prune_walk_per_space_limit: usize,
    /// Round R2/R3 (T08) — deployment trust domain id, used to bind
    /// `cx.cross_signing.reset` events to this Principal Server so the
    /// same proof bytes cannot be replayed cross-domain. Loaded from
    /// `SOLAND_TRUST_DOMAIN` (must match `cx:trust_domain:<scope>`,
    /// scope = lowercase alphanumerics/dot/dash/underscore/colon ≤128 chars).
    /// Defaults to `cx:trust_domain:<host_of_service_did>`.
    pub trust_domain: String,
    /// When true, `AppState::new` seeds a deterministic demo Space
    /// (`cx:space:0196419b-...`), demo account (`did:web:alice.example`),
    /// and matching space_meta record on boot. Off by default so
    /// production deployments don't ship a globally-shared "demo" Space
    /// that collides across federated peers. Test harnesses opt in via
    /// `test_config()` to keep their fixture IDs stable.
    /// Env: `SOLAND_SEED_DEMO_DATA` (default false).
    pub seed_demo_data: bool,
    /// G3.S9 — when true, soland claims `cx.profile.sovereign_enclave.v1`
    /// on `/server/describe` and enforces the enclave invariants
    /// (`routing::extensions::sovereign::assert_enclave_invariants`):
    /// outbound federation OFF, DID resolver method allow-list
    /// non-empty, every outbound HTTP call gated through
    /// [`crate::routing::extensions::sovereign::outbound_allowed`].
    /// Env: `SOLAND_SOVEREIGN_ENCLAVE` (default false).
    pub sovereign_enclave_enabled: bool,
    /// G3.S9 — host allow-list for outbound HTTP when the enclave
    /// profile is enabled. Hosts are matched case-insensitively.
    /// Comma-separated env var
    /// `SOLAND_SOVEREIGN_ENCLAVE_ALLOWED_OUTBOUND_HOSTS`.
    pub sovereign_enclave_allowed_outbound_hosts: Vec<String>,
    /// Stream-F (Wave 2C) — cross-Principal-Server erasure-receipt
    /// propagation window in milliseconds. After a
    /// `cx.audit.erasure_receipt` is accepted, the federation fanout
    /// worker waits up to this many ms for every peer to acknowledge.
    /// Peers that don't respond inside the window flip the receipt's
    /// top-level `fanout_status` to `incomplete`. Spec
    /// `realm-and-space.md` §2.5.2: default 7 days (604_800_000 ms).
    /// Env: `SOLAND_ERASURE_PROPAGATION_WINDOW_MS`.
    pub erasure_propagation_window_ms: u64,
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

/// Federation routing policy. Selected at config-load
/// time via `SOLAND_FEDERATION_POLICY` env var (`mesh` | `hub`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FederationPolicy {
    /// Default — broadcast every accepted Move to every peer in
    /// [`AppConfig::federation_peers`].
    Mesh,
    /// Push to a single upstream hub. The first entry in
    /// [`AppConfig::federation_peers`] is the hub.
    Hub,
}

impl FederationPolicy {
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

/// Provenance tag for the AnchorerWorker's signing key. Surfaced
/// on each signing pass so logs flag the dev-only ephemeral path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnchorerSigningKeyOrigin {
    /// Loaded from `SOLAND_ANCHORER_SIGNING_KEY` (production-grade
    /// persistent identity).
    Configured,
    /// In-process random seed — fine for tests, **never** for production:
    /// every restart issues Anchors under a brand-new DID, breaking
    /// signature-chain trust.
    Ephemeral,
}

impl AppConfig {
    /// Spec-recommended per-cell-family replay-window overrides.
    /// Tighter windows for safety-critical / authority cells; the global
    /// default still applies to everything else.
    pub fn default_replay_overrides() -> std::collections::BTreeMap<&'static str, u64> {
        let mut m = std::collections::BTreeMap::new();
        m.insert("cx.component.anchorer.v1", 60);
        m.insert("cx.component.mls.epoch.v1", 60);
        m.insert("cx.component.consent.grant.v1", 120);
        m.insert("cx.component.capability.grant.v1", 120);
        m.insert("cx.component.capability.delegate.v1", 120);
        m.insert("cx.component.capability.derived.v1", 120);
        m
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
        let service_did = std::env::var("SOLAND_SERVICE_DID")
            .unwrap_or_else(|_| "did:web:soland.local".to_owned());
        let tls_cert_path = env_non_empty("SOLAND_TLS_CERT_PATH").map(PathBuf::from);
        let tls_key_path = env_non_empty("SOLAND_TLS_KEY_PATH").map(PathBuf::from);
        if tls_cert_path.is_some() != tls_key_path.is_some() {
            anyhow::bail!("SOLAND_TLS_CERT_PATH and SOLAND_TLS_KEY_PATH must be set together");
        }
        let database_url = std::env::var("DATABASE_URL")
            .ok()
            .filter(|value| !value.trim().is_empty());
        let object_storage = load_object_storage_config()?;
        let auth_server_url = env_non_empty("SOLAND_AUTH_SERVER_URL");
        // Default to a production-safe posture (no `dev_login`, no relaxed DID
        // validation, no admin snapshot endpoints). Local development must opt
        // in explicitly via `SOLAND_DEVELOPMENT_MODE=true`.
        let development_mode = std::env::var("SOLAND_DEVELOPMENT_MODE")
            .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes"))
            .unwrap_or(false);
        // CORS posture per api-conventions.md §10 — browser clients SHOULD be
        // able to reach us via preflight. Three shapes:
        //   - env unset, production mode → `None` (no CORS handler at all;
        //     operator must opt in explicitly for browser access)
        //   - env unset, development mode → defaults to `Some("*")`, the
        //     spec-recommended permissive default for local / loopback work
        //     so plain `cargo run` of soland is reachable from a yougen
        //     dev server without extra env wiring
        //   - env set → use as-is. `"*"` installs the permissive (mirror
        //     origin, no credentials) handler; any other value is treated
        //     as an explicit origin allow-list and installs the credentialed
        //     handler. See `routing::cors_handler_for_config`.
        let cors_allow_origin = std::env::var("SOLAND_CORS_ALLOW_ORIGIN")
            .ok()
            .map(|v| v.trim().to_owned())
            .filter(|v| !v.is_empty())
            .or_else(|| development_mode.then(|| "*".to_owned()));
        let oauth_introspection_url = env_non_empty("SOLAND_OAUTH_INTROSPECTION_URL");
        let oauth_introspection_bearer =
            env_non_empty_or_file("SOLAND_OAUTH_INTROSPECTION_BEARER")?;
        let session_grant_introspection_url =
            env_non_empty("SOLAND_SESSION_GRANT_INTROSPECTION_URL");
        let session_grant_introspection_bearer =
            env_non_empty_or_file("SOLAND_SESSION_GRANT_INTROSPECTION_BEARER")?;
        let did_resolver_allow_methods = env_csv("SOLAND_DID_RESOLVER_ALLOW_METHODS")
            .unwrap_or_else(|| vec!["web".to_owned(), "key".to_owned(), "uuid".to_owned()]);
        let embedded_webvh_provider_enabled =
            env_bool("SOLAND_EMBEDDED_WEBVH_PROVIDER_ENABLED")?.unwrap_or(true);
        let embedded_webvh_registration_bearer =
            env_non_empty_or_file("SOLAND_EMBEDDED_WEBVH_REGISTRATION_BEARER")?;
        let external_webvh_provider_url = env_non_empty("SOLAND_EXTERNAL_WEBVH_PROVIDER_URL");
        let default_webvh_provider_id = env_non_empty("SOLAND_DEFAULT_WEBVH_PROVIDER_ID");
        // 0 disables replay-window enforcement; default 5 min per spec.
        let jws_replay_window_seconds = std::env::var("SOLAND_JWS_REPLAY_WINDOW_SECONDS")
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .unwrap_or(300);
        let anchorer_signing_key_seed = load_anchorer_signing_key_seed()?;
        let agent_audit_binding_signing_seed = load_agent_audit_binding_signing_seed()?;
        let use_keystore = std::env::var("SOLAND_USE_KEYSTORE")
            .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes"))
            .unwrap_or(false);
        let federation_policy = std::env::var("SOLAND_FEDERATION_POLICY")
            .ok()
            .map(|value| FederationPolicy::from_env_value(&value))
            .unwrap_or(FederationPolicy::Mesh);
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
        let push_bridge_cache_ttl_seconds = std::env::var("SOLAND_PUSH_BRIDGE_CACHE_TTL_SECS")
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .unwrap_or(900);
        let push_bridge_trusted_service_dids =
            std::env::var("SOLAND_PUSH_BRIDGE_TRUSTED_SERVICE_DIDS")
                .ok()
                .map(|value| {
                    value
                        .split(',')
                        .map(|v| v.trim().to_owned())
                        .filter(|v| !v.is_empty())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
        let compaction_min_anchor_age_seconds =
            std::env::var("SOLAND_COMPACTION_MIN_ANCHOR_AGE_SECS")
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
        let compaction_prune_walk_per_space_limit =
            std::env::var("SOLAND_COMPACTION_PRUNE_WALK_PER_SPACE_LIMIT")
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
        let trust_domain = derive_trust_domain(&service_did)?;

        Ok(Self {
            bind,
            metrics_bind,
            public_base_url,
            service_did,
            tls_cert_path,
            tls_key_path,
            database_url,
            object_storage,
            cors_allow_origin,
            auth_server_url,
            development_mode,
            oauth_introspection_url,
            oauth_introspection_bearer,
            session_grant_introspection_url,
            session_grant_introspection_bearer,
            did_resolver_allow_methods,
            embedded_webvh_provider_enabled,
            embedded_webvh_registration_bearer,
            external_webvh_provider_url,
            // `main.rs` flips this to true after a successful boot probe.
            external_webvh_provider_active: false,
            default_webvh_provider_id,
            jws_replay_window_seconds,
            jws_replay_window_per_family: Self::default_replay_overrides(),
            anchorer_signing_key_seed,
            agent_audit_binding_signing_seed,
            use_keystore,
            federation_policy,
            federation_peers,
            federation_outbound_enabled,
            admin_default_page_limit,
            admin_max_page_limit,
            admin_principal_dids,
            push_bridge_cache_ttl_seconds,
            push_bridge_trusted_service_dids,
            compaction_min_anchor_age_seconds,
            compaction_min_witnesses,
            compaction_preserve_genesis,
            compaction_prune_only_singleton_successors,
            compaction_prune_walk_interval_seconds,
            compaction_prune_walk_per_space_limit,
            seed_demo_data,
            trust_domain,
            sovereign_enclave_enabled,
            sovereign_enclave_allowed_outbound_hosts,
            erasure_propagation_window_ms,
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
    /// in `/health` and `/api/v1/server/describe`:
    ///
    ///   - `"development"` — `SOLAND_DEVELOPMENT_MODE=true`; any authenticated
    ///     session may call admin endpoints.
    ///   - `"did_allowlist"` — production mode, `SOLAND_ADMIN_PRINCIPAL_DIDS`
    ///     is non-empty; admin endpoints accept calls whose session actor
    ///     appears in the allowlist.
    ///   - `"oauth_introspection"` — production mode, no DID allowlist but
    ///     OAuth bearer introspection is configured. Any token coauth
    ///     introspects as valid passes.
    ///   - `"closed"` — production mode with neither admin allowlist nor
    ///     introspection configured; admin endpoints are effectively locked.
    pub fn admin_auth_mode(&self) -> &'static str {
        if self.development_mode {
            "development"
        } else if !self.admin_principal_dids.is_empty() {
            "did_allowlist"
        } else if self.oauth_introspection_url.is_some() {
            "oauth_introspection"
        } else {
            "closed"
        }
    }

    /// String mirror of [`Self::development_mode`]: `"development"` or
    /// `"production"`. Exposed on `/health` and `/api/v1/server/describe`
    /// so operators can see at a glance whether proof verification is
    /// running in the relaxed dev-mode path.
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
    /// [`contrix_sdk::CompactionPolicy::is_eligible`].
    pub fn compaction_policy(&self) -> contrix_sdk::CompactionPolicy {
        contrix_sdk::CompactionPolicy {
            min_anchor_age_seconds: self.compaction_min_anchor_age_seconds,
            min_compaction_witnesses: self.compaction_min_witnesses,
            preserve_genesis: self.compaction_preserve_genesis,
            prune_only_singleton_successors: self.compaction_prune_only_singleton_successors,
        }
    }

    #[inline]
    pub fn tls_enabled(&self) -> bool {
        self.tls_cert_path.is_some() && self.tls_key_path.is_some()
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
        // Soland does not yet integrate with a remote secret manager —
        // signing seeds come from env vars. We treat "env-provided
        // signing seed" as the minimum acceptable production posture
        // and surface a warning when it is missing.
        let secret_manager_in_use = self.anchorer_signing_key_seed.is_some() || self.use_keystore;
        // Log redaction is structurally enforced by the tracing layer
        // (no PII fields are logged at INFO); we report true unless dev
        // mode flips us into the chatty path.
        let log_redaction_enabled = !development_mode;
        let admin_auth_mode = self.admin_auth_mode().to_owned();
        // Rate limiter is unconditionally installed by `router()`.
        let rate_limit_enabled = true;
        // Provider credential rotation: soland's only signing identity
        // is the anchorer key; rotation is manual today. The KeyStore
        // path is the closest thing to "scheduled" we ship.
        let provider_credential_rotation = if self.use_keystore {
            "scheduled".to_owned()
        } else if self.anchorer_signing_key_seed.is_some() {
            "manual".to_owned()
        } else {
            "none".to_owned()
        };

        let checks = [
            ("development_mode_disabled", !development_mode),
            ("tls_enabled", tls_enabled),
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

        crate::wire::HardeningStatus {
            development_mode,
            tls_enabled,
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

/// Load the AnchorerWorker signing seed from
/// `SOLAND_ANCHORER_SIGNING_KEY` (base64-standard encoded 32 bytes).
/// Returns `Ok(None)` when the env var is absent or empty (the
/// AnchorerWorker then mints an ephemeral key with a sticky-warn).
/// Returns `Err(_)` when the env var is set but malformed — fail-fast at
/// startup rather than silently downgrading to ephemeral.
fn load_anchorer_signing_key_seed() -> anyhow::Result<Option<[u8; 32]>> {
    let raw = match std::env::var("SOLAND_ANCHORER_SIGNING_KEY") {
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
                "SOLAND_ANCHORER_SIGNING_KEY must be base64 (standard or url-safe-no-pad): {e}"
            )
        })?;
    if bytes.len() != 32 {
        anyhow::bail!(
            "SOLAND_ANCHORER_SIGNING_KEY must decode to exactly 32 bytes (got {})",
            bytes.len()
        );
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    Ok(Some(seed))
}

/// Env-loaded Ed25519 seed for the reference agent runtime's
/// `audit_binding` signer. Same shape rules as
/// [`load_anchorer_signing_key_seed`] — base64-standard or
/// url-safe-no-pad, MUST decode to exactly 32 bytes.
fn load_agent_audit_binding_signing_seed() -> anyhow::Result<Option<[u8; 32]>> {
    let raw = match std::env::var("SOLAND_AGENT_AUDIT_BINDING_SIGNING_SEED") {
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
                "SOLAND_AGENT_AUDIT_BINDING_SIGNING_SEED must be base64 (standard or url-safe-no-pad): {e}"
            )
        })?;
    if bytes.len() != 32 {
        anyhow::bail!(
            "SOLAND_AGENT_AUDIT_BINDING_SIGNING_SEED must decode to exactly 32 bytes (got {})",
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
/// 1. `SOLAND_TRUST_DOMAIN` env var if set (must validate as
///    `cx:trust_domain:<scope>` per SDK [`contrix_sdk::TypedTrustDomainId`]).
/// 2. Synthesised from the configured `service_did` — strip the DID method
///    prefix and lowercase the remainder, then prefix with
///    `cx:trust_domain:`.
fn derive_trust_domain(service_did: &str) -> anyhow::Result<String> {
    if let Some(value) = env_non_empty("SOLAND_TRUST_DOMAIN") {
        // Validate via SDK typed id — rejects bad shape at boot.
        contrix_sdk::TypedTrustDomainId::new(value.clone()).map_err(|e| {
            anyhow::anyhow!("SOLAND_TRUST_DOMAIN must be cx:trust_domain:<scope>: {e}")
        })?;
        return Ok(value);
    }
    let host = service_did
        .strip_prefix("did:web:")
        .or_else(|| service_did.strip_prefix("did:key:"))
        .or_else(|| service_did.strip_prefix("did:webvh:"))
        .unwrap_or(service_did);
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
    let candidate = format!("cx:trust_domain:{scope}");
    // Final safety check.
    contrix_sdk::TypedTrustDomainId::new(candidate.clone()).map_err(|e| {
        anyhow::anyhow!(
            "derived trust_domain from service_did {service_did:?} failed validation: {e}"
        )
    })?;
    Ok(candidate)
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
mod tests {
    use super::*;

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
}
