use std::{net::SocketAddr, path::PathBuf};

#[derive(Clone, Debug)]
pub struct AppConfig {
    pub bind: SocketAddr,
    pub public_base_url: String,
    pub service_did: String,
    pub database_url: Option<String>,
    pub blob_root: PathBuf,
    pub cors_allow_origin: Option<String>,
    pub development_mode: bool,
    pub session_grant_introspection_url: Option<String>,
    pub session_grant_introspection_bearer: Option<String>,
    pub did_resolver_allow_methods: Vec<String>,
    pub starid_webvh_resolver_url: Option<String>,
    /// C10.B (2026-05-09 十二轮) JWS replay protection window in seconds.
    /// Move and Anchor signatures whose signed `hlc` is older than
    /// `now - replay_window_seconds` OR newer than `now +
    /// replay_window_seconds` are rejected.
    ///
    /// Default 300s = 5 min — matches the Contrix spec recommendation in
    /// `signatures-and-replay.md`. Set to `0` to disable (dev / tests
    /// using fixed-time fixtures rely on this; production deployments
    /// MUST keep this > 0).
    pub jws_replay_window_seconds: u64,
    /// C10.B (2026-05-09 十四轮) per-cell-family replay-window overrides.
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
    /// Round 22 default-true `lattice_first` flag (see doc comment above).
    pub lattice_first: bool,
    /// Round 22 — base64-encoded 32-byte ed25519 seed for the AnchorerWorker
    /// signing identity (env `SERVERX_ANCHORER_SIGNING_KEY`). When `Some(_)`
    /// the worker uses a deterministic ed25519-dalek signing key derived
    /// from this seed; when `None` the worker boots with an in-process
    /// random ephemeral key and a sticky-warn log line on every signing
    /// pass, matching the [`AnchorerSigningKeyOrigin::Ephemeral`] branch.
    ///
    /// Loading is identical to coauth's session-grant signing-key pattern
    /// — the env var holds the raw seed, base64-standard-padded; bad shape
    /// fails fast at startup with a clear error.
    pub anchorer_signing_key_seed: Option<[u8; 32]>,
}

/// Round 22 — provenance tag for the AnchorerWorker's signing key. Surfaced
/// on each signing pass so logs flag the dev-only ephemeral path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnchorerSigningKeyOrigin {
    /// Loaded from `SERVERX_ANCHORER_SIGNING_KEY` (production-grade
    /// persistent identity).
    Configured,
    /// In-process random seed — fine for tests, **never** for production:
    /// every restart issues Anchors under a brand-new DID, breaking
    /// signature-chain trust.
    Ephemeral,
}

impl AppConfig {
    /// Spec-recommended per-cell-family replay-window overrides (十四轮).
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
            .or_else(|| std::env::var("SERVERX_BIND").ok())
            .unwrap_or_else(|| "127.0.0.1:8787".to_owned())
            .parse()?;
        let public_base_url =
            std::env::var("SERVERX_PUBLIC_BASE_URL").unwrap_or_else(|_| format!("http://{bind}"));
        let service_did = std::env::var("SERVERX_SERVICE_DID")
            .unwrap_or_else(|_| "did:web:soland.local".to_owned());
        let database_url = std::env::var("DATABASE_URL")
            .ok()
            .filter(|value| !value.trim().is_empty());
        let blob_root = std::env::var("SERVERX_BLOB_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|_| std::env::temp_dir().join("soland-blobs"));
        let cors_allow_origin = std::env::var("SERVERX_CORS_ALLOW_ORIGIN").ok();
        // Default to a production-safe posture (no `dev_login`, no relaxed DID
        // validation, no admin snapshot endpoints). Local development must opt
        // in explicitly via `SERVERX_DEVELOPMENT_MODE=true`.
        let development_mode = std::env::var("SERVERX_DEVELOPMENT_MODE")
            .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes"))
            .unwrap_or(false);
        let session_grant_introspection_url =
            env_non_empty("SERVERX_SESSION_GRANT_INTROSPECTION_URL");
        let session_grant_introspection_bearer =
            env_non_empty("SERVERX_SESSION_GRANT_INTROSPECTION_BEARER");
        let did_resolver_allow_methods = env_csv("SERVERX_DID_RESOLVER_ALLOW_METHODS")
            .unwrap_or_else(|| vec!["web".to_owned(), "key".to_owned(), "uuid".to_owned()]);
        let starid_webvh_resolver_url = env_non_empty("SERVERX_STARID_WEBVH_RESOLVER_URL");
        // 0 disables replay-window enforcement; default 5 min per spec.
        let jws_replay_window_seconds = std::env::var("SERVERX_JWS_REPLAY_WINDOW_SECONDS")
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .unwrap_or(300);
        // Round 22: `lattice_first` defaults to **true** — full LatticeRegistry
        // takeover for ProjectionState::apply. Override to `false` only for
        // incident-response triage of event_kind classifier regressions.
        let lattice_first = std::env::var("SERVERX_LATTICE_FIRST")
            .map(|value| !matches!(value.as_str(), "0" | "false" | "FALSE" | "no"))
            .unwrap_or(true);
        let anchorer_signing_key_seed = load_anchorer_signing_key_seed()?;

        Ok(Self {
            bind,
            public_base_url,
            service_did,
            database_url,
            blob_root,
            cors_allow_origin,
            development_mode,
            session_grant_introspection_url,
            session_grant_introspection_bearer,
            did_resolver_allow_methods,
            starid_webvh_resolver_url,
            jws_replay_window_seconds,
            jws_replay_window_per_family: Self::default_replay_overrides(),
            lattice_first,
            anchorer_signing_key_seed,
        })
    }
}

/// Round 22 — load the AnchorerWorker signing seed from
/// `SERVERX_ANCHORER_SIGNING_KEY` (base64-standard encoded 32 bytes).
/// Returns `Ok(None)` when the env var is absent or empty (the
/// AnchorerWorker then mints an ephemeral key with a sticky-warn).
/// Returns `Err(_)` when the env var is set but malformed — fail-fast at
/// startup rather than silently downgrading to ephemeral.
fn load_anchorer_signing_key_seed() -> anyhow::Result<Option<[u8; 32]>> {
    let raw = match std::env::var("SERVERX_ANCHORER_SIGNING_KEY") {
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
                "SERVERX_ANCHORER_SIGNING_KEY must be base64 (standard or url-safe-no-pad): {e}"
            )
        })?;
    if bytes.len() != 32 {
        anyhow::bail!(
            "SERVERX_ANCHORER_SIGNING_KEY must decode to exactly 32 bytes (got {})",
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

fn arg_value(name: &str) -> Option<String> {
    let mut args = std::env::args();
    while let Some(arg) = args.next() {
        if arg == name {
            return args.next();
        }
    }
    None
}
