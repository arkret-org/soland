use std::{net::SocketAddr, path::PathBuf};

#[derive(Clone, Debug)]
pub struct AppConfig {
    pub bind: SocketAddr,
    pub public_base_url: String,
    pub service_did: String,
    pub database_url: Option<String>,
    pub object_storage: ObjectStorageConfig,
    pub cors_allow_origin: Option<String>,
    pub development_mode: bool,
    pub session_grant_introspection_url: Option<String>,
    pub session_grant_introspection_bearer: Option<String>,
    pub did_resolver_allow_methods: Vec<String>,
    /// Configured starid `did:webvh` resolver URL. Records **admin intent** —
    /// always reflects whatever was passed via `SOLAND_STARID_WEBVH_RESOLVER_URL`,
    /// regardless of whether the upstream is currently reachable. The `/identity/describe`
    /// handler surfaces this as `starid_profile.enabled` so admin / sibling services
    /// can discover the configured profile even when the upstream is down.
    pub starid_webvh_resolver_url: Option<String>,
    /// Runtime liveness flag for the `did:webvh` resolver chain entry.
    /// `true` only when [`probe_starid_describe`] succeeded at boot; consumed by
    /// [`build_did_resolver_chain`] to decide whether to actually mount the
    /// `DidWebvhResolver` in the chain. Decoupling intent (`starid_webvh_resolver_url`)
    /// from liveness (`starid_webvh_resolver_active`) prevents the boot probe
    /// from silently disabling profile discovery.
    pub starid_webvh_resolver_active: bool,
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
    /// When true, the AnchorerWorker loads its signing seed
    /// from the SDK platform `KeyStore` (`platform_default_keystore("soland.<service_did>")`)
    /// at boot and stores rotated keys back into the same KeyStore. When
    /// false (default), only `anchorer_signing_key_seed` (env-loaded) is
    /// honored. The KeyStore key id is `contrix:signer:soland-anchorer:<service_did>`.
    ///
    /// Behavior when `use_keystore=true`:
    /// - First boot: try `KeyStore::load(...)`; on `not_found` fall back to
    ///   `anchorer_signing_key_seed`; if that's also absent, mint a fresh
    ///   seed and persist it via `KeyStore::store(...)` (one-shot init).
    /// - `rotate-signing-key` endpoint: mint, persist via KeyStore, hot-swap.
    ///
    /// Behavior when `use_keystore=false`: identical to round 22.
    pub use_keystore: bool,
    /// Federation routing policy. The on-the-wire
    /// shape is identical for both variants (Move broadcast push / Anchor
    /// pull-push under `/api/v1/federation/{push-operations,anchors,...}`);
    /// the policy only changes which set of peer endpoints we talk to.
    ///
    /// - [`FederationPolicy::Mesh`] — broadcast each accepted Move to every
    ///   known peer (gossip-like). Anchors are replicated via pull-push
    ///   when peer pressure spikes. Default.
    /// - [`FederationPolicy::Hub`] — push only to a single configured
    ///   upstream hub; rely on the hub for outbound dissemination.
    pub federation_policy: FederationPolicy,
    /// Peer DIDs the federation outbound layer
    /// considers as broadcast targets (mesh) or hub upstream (hub). Empty
    /// disables federation outbound.
    pub federation_peers: Vec<String>,
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
        let public_base_url =
            std::env::var("SOLAND_PUBLIC_BASE_URL").unwrap_or_else(|_| format!("http://{bind}"));
        let service_did = std::env::var("SOLAND_SERVICE_DID")
            .unwrap_or_else(|_| "did:web:soland.local".to_owned());
        let database_url = std::env::var("DATABASE_URL")
            .ok()
            .filter(|value| !value.trim().is_empty());
        let object_storage = load_object_storage_config()?;
        let cors_allow_origin = std::env::var("SOLAND_CORS_ALLOW_ORIGIN").ok();
        // Default to a production-safe posture (no `dev_login`, no relaxed DID
        // validation, no admin snapshot endpoints). Local development must opt
        // in explicitly via `SOLAND_DEVELOPMENT_MODE=true`.
        let development_mode = std::env::var("SOLAND_DEVELOPMENT_MODE")
            .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes"))
            .unwrap_or(false);
        let session_grant_introspection_url =
            env_non_empty("SOLAND_SESSION_GRANT_INTROSPECTION_URL");
        let session_grant_introspection_bearer =
            env_non_empty("SOLAND_SESSION_GRANT_INTROSPECTION_BEARER");
        let did_resolver_allow_methods = env_csv("SOLAND_DID_RESOLVER_ALLOW_METHODS")
            .unwrap_or_else(|| vec!["web".to_owned(), "key".to_owned(), "uuid".to_owned()]);
        let starid_webvh_resolver_url = env_non_empty("SOLAND_STARID_WEBVH_RESOLVER_URL");
        // 0 disables replay-window enforcement; default 5 min per spec.
        let jws_replay_window_seconds = std::env::var("SOLAND_JWS_REPLAY_WINDOW_SECONDS")
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .unwrap_or(300);
        let anchorer_signing_key_seed = load_anchorer_signing_key_seed()?;
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

        Ok(Self {
            bind,
            public_base_url,
            service_did,
            database_url,
            object_storage,
            cors_allow_origin,
            development_mode,
            session_grant_introspection_url,
            session_grant_introspection_bearer,
            did_resolver_allow_methods,
            starid_webvh_resolver_url,
            // `main.rs` flips this to true after a successful boot probe.
            // Default false: until proven reachable, the resolver is not mounted
            // even if the URL is configured. Intent (URL) and liveness (active)
            // are independent.
            starid_webvh_resolver_active: false,
            jws_replay_window_seconds,
            jws_replay_window_per_family: Self::default_replay_overrides(),
            anchorer_signing_key_seed,
            use_keystore,
            federation_policy,
            federation_peers,
        })
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
