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
    /// Round 21 — opt-in flag that routes `ProjectionState::apply()` through
    /// the [`crate::reducer::registry::LatticeRegistry`] lookup before
    /// falling back to the legacy per-domain `match` dispatcher. Default
    /// `false`: today the registry only carries cell_family metadata for
    /// Move/Anchor effect dispatch — durable Events still drive the
    /// structured projection cache via inline `apply_*` helpers. Once the
    /// `event_kind → cell_family → lattice op` mapping table is filled in
    /// (per cell-family LatticeKind impl exposing a `event_kinds()`
    /// declaration), flipping this flag will let the registry handle the
    /// dispatch entirely. Set via env `SERVERX_LATTICE_FIRST=true`.
    pub lattice_first: bool,
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
        let lattice_first = std::env::var("SERVERX_LATTICE_FIRST")
            .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes"))
            .unwrap_or(false);

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
        })
    }
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
