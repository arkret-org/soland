use anyhow::Context;
use salvo::conn::Acceptor;
use salvo::conn::rustls::{Keycert, RustlsConfig};
use salvo::prelude::*;
use soland::config::AppConfig;
use soland::db::Db;
use soland::multisig_watchdog::{MultisigWatchdog, MultisigWatchdogConfig};
use soland::state::AppState;
use soland::{artifacts, service};
use tokio::signal;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    // P5 (5.5) — `soland healthcheck` subcommand. Distroless / minimal
    // runtime images cannot rely on an external `curl` binary for the
    // Docker HEALTHCHECK. Detect the subcommand BEFORE we initialize
    // tracing so the healthcheck process stays quiet (no startup chatter,
    // no opening of SOLAND_LOG_FILE), exits with status 0 on probe
    // success and 1 on failure, and never starts the Salvo listener.
    let raw_args: Vec<String> = std::env::args().collect();
    if raw_args
        .iter()
        .skip(1)
        .any(|arg| arg == "healthcheck" || arg == "--healthcheck")
    {
        return run_healthcheck(&raw_args).await;
    }

    // Keep this guard alive for the process lifetime so the non-blocking
    // file appender drains its channel on shutdown. Dropping the guard
    // flushes pending writes; storing it in `_file_guard` defers that drop
    // until `main` returns.
    // We need to read SOLAND_DEVELOPMENT_MODE + SOLAND_LOG_FORMAT before
    // building the subscriber so production deployments get structured JSON
    // logs by default. Use the same env helper the rest of the loader uses.
    let dev_mode_for_logging = std::env::var("SOLAND_DEVELOPMENT_MODE")
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes"))
        .unwrap_or(false);
    let log_format = soland::config::LogFormat::from_env(dev_mode_for_logging);
    let _tracing_guards = init_tracing(log_format)?;

    // Fail fast at startup if a bundled Cokret artifact is malformed instead
    // of crashing the first request that touches the offending OnceLock.
    artifacts::validate_embedded_artifacts()?;

    let mut config = AppConfig::from_env_and_args()?;
    if let Some(database_url) = &config.database_url {
        // SAFETY: invoked once, before any worker thread starts touching the
        // env, so there is no concurrent reader. Diesel's `Pool::builder`
        // reads `DATABASE_URL` internally; pushing the parsed value back into
        // the env keeps that path working when the URL came from `--bind`-
        // style arg parsing.
        unsafe {
            std::env::set_var("DATABASE_URL", database_url);
        }
    }
    // Probe the optional external webvh provider before advertising it as
    // active. The configured URL remains visible in `/identity/describe` even
    // when the probe fails so coauth can show the operator's intended setup.
    if let Some(url) = config.external_webvh_provider_url.clone() {
        let expected_service_did = std::env::var("SOLAND_EXTERNAL_WEBVH_PROVIDER_SERVICE_DID").ok();
        let expected_trust_domain = std::env::var("SOLAND_EXTERNAL_WEBVH_PROVIDER_TRUST_DOMAIN")
            .ok()
            .unwrap_or_else(|| config.trust_domain.clone());
        match soland::state::did_resolver_chain::probe_webvh_provider_describe(
            &url,
            std::time::Duration::from_secs(3),
            expected_service_did.as_deref(),
            Some(expected_trust_domain.as_str()),
            config.development_mode,
        )
        .await
        {
            Ok(()) => {
                tracing::info!(
                    webvh_provider_url = %url,
                    "external webvh provider /describe probe succeeded"
                );
                config.external_webvh_provider_active = true;
            }
            Err(error) => {
                tracing::warn!(
                    webvh_provider_url = %url,
                    %error,
                    "external webvh provider /describe probe failed"
                );
            }
        }
    }
    let state = AppState::new(config.clone(), Db::from_env().await?);
    // Finish boot: seed demo data + hydrate the Realm directory and
    // projections from the (now async) persistence store.
    state.hydrate().await;

    // G3.S9 — sovereign enclave profile invariants. When
    // `SOLAND_SOVEREIGN_ENCLAVE=1` the configured posture MUST satisfy:
    //   * federation_outbound_enabled = false
    //   * did_resolver_allow_methods non-empty
    // Fail fast at startup if either invariant is violated; the enclave
    // profile claim on `/server/describe` would otherwise be a lie.
    let enclave_assertion =
        soland::routing::extensions::sovereign::assert_enclave_invariants(&state.config);
    if !enclave_assertion.is_compliant() {
        anyhow::bail!(
            "SOLAND_SOVEREIGN_ENCLAVE=1 but enclave invariants are not satisfied: {}",
            enclave_assertion.violations.join("; ")
        );
    }
    if enclave_assertion.enabled {
        tracing::info!(
            target: "sovereign_boundary_audit",
            allowed_outbound_hosts = ?state.config.sovereign_enclave_allowed_outbound_hosts,
            "sovereign enclave profile enabled; outbound federation is disabled \
             and outbound HTTP must be on the allow-list",
        );
    }

    // Spawn the multisig leader-election watchdog. The task wakes every
    // 30s by default, scans `multisig_pending` for rows
    // whose threshold is met + canonical_b64 is non-empty, claims an
    // unleased row, and aggregates via SDK `ThresholdAggregator`. Returns
    // a JoinHandle we drop on the floor — the task lives for the process
    // lifetime and shutdown_signal teardown closes the runtime.
    let watchdog_config = MultisigWatchdogConfig::for_service(&state.config.service_did);
    let _watchdog = MultisigWatchdog::new(state.clone(), watchdog_config).spawn();
    tracing::info!(
        worker = "multisig_watchdog",
        enabled = true,
        service_did = %state.config.service_did,
        "background worker configured"
    );

    // MAL-11 compaction prune walk worker. No-op when
    // `SOLAND_COMPACTION_PRUNE_WALK_INTERVAL_SECS=0` (the default) — the
    // explicit `POST /admin/spaces/{space_id}/anchor-dag/prune`
    // endpoint stays operator-driven. Set the env var to enable periodic
    // walking; see `compactor.rs` for the policy and "when to enable"
    // rationale.
    let _compactor = soland::compactor::spawn(state.clone());
    tracing::info!(
        worker = "compactor",
        enabled = state.config.compaction_prune_walk_interval_seconds > 0,
        interval_seconds = state.config.compaction_prune_walk_interval_seconds,
        "background worker configured"
    );

    // G3.S0 — durable outbound federation HTTP delivery worker. No-op
    // when `SOLAND_FEDERATION_OUTBOUND=0` (used by integration tests
    // that don't want background HTTP traffic). The dispatcher drains
    // the `federation_outbox` table populated by
    // `routing::federation::federation::broadcast_*_to_peers`.
    let _federation_dispatcher = soland::routing::federation::outbox::spawn(state.clone());
    tracing::info!(
        worker = "federation_outbox",
        enabled = state.config.federation_outbound_enabled,
        "background worker configured"
    );

    // Stream-F (Wave 2C) — periodic erasure-receipt federation fanout
    // timeout sweep. Wakes every hour (the default sweep interval; the
    // spec window is 7 days so missing a tick can only delay the
    // `incomplete` flip by ~1h), scans `erasure_receipts` for receipts
    // whose `recorded_at + erasure_propagation_window_ms` has lapsed
    // with at least one peer still un-acknowledged, and flips
    // `fanout_status = "incomplete"`. Spec
    // `realm-and-space.md` §2.5.2. Same `federation_outbound_enabled`
    // toggle as the dispatcher above.
    let _erasure_fanout_sweep = soland::routing::federation::erasure_fanout::spawn(state.clone());
    tracing::info!(
        worker = "erasure_fanout_sweep",
        enabled = state.config.federation_outbound_enabled,
        propagation_window_ms = state.config.erasure_propagation_window_ms,
        "background worker configured"
    );

    let _metrics_server =
        soland::metrics::spawn_metrics_server(state.clone(), config.metrics_bind).await?;
    tracing::info!(
        worker = "metrics_server",
        bind = %config.metrics_bind,
        "background worker configured"
    );

    tracing::info!(
        bind = %config.bind,
        metrics_bind = %config.metrics_bind,
        public_base_url = %config.public_base_url,
        service_did = %config.service_did,
        tls_enabled = config.tls_enabled(),
        tls_cert_path = ?config.tls_cert_path,
        tls_key_path = ?config.tls_key_path,
        embedded_webvh_provider_enabled = config.embedded_webvh_provider_enabled,
        external_webvh_provider_url = ?config.external_webvh_provider_url,
        object_storage_backend = %config.object_storage.backend_name(),
        object_storage_target = %config.object_storage.log_target(),
        development_mode = config.development_mode,
        storage = state.db.mode(),
        "starting soland"
    );
    if config.tls_enabled() {
        let keycert = Keycert::new()
            .cert_from_path(
                config
                    .tls_cert_path
                    .as_ref()
                    .expect("tls_enabled guarantees cert path"),
            )
            .context("failed to read SOLAND_TLS_CERT_PATH")?
            .key_from_path(
                config
                    .tls_key_path
                    .as_ref()
                    .expect("tls_enabled guarantees key path"),
            )
            .context("failed to read SOLAND_TLS_KEY_PATH")?;
        let acceptor = TcpListener::new(config.bind.to_string())
            .rustls(RustlsConfig::new(keycert))
            .bind()
            .await;
        tracing::info!(
            event = "tls_listener_enabled",
            tls_provider = "rustls",
            bind = %config.bind,
            "TLS listener enabled"
        );
        run_server(acceptor, state).await;
    } else {
        let acceptor = TcpListener::new(config.bind.to_string()).bind().await;
        run_server(acceptor, state).await;
    }
    tracing::info!(event = "shutdown_complete", "soland stopped");
    Ok(())
}

/// Build the tracing subscriber.
///
/// Always writes to stdout (the default, interactive-friendly destination —
/// `cargo run` users see logs as usual). When `SOLAND_LOG_FILE` is set we
/// additionally tee output to that path through a non-blocking appender so
/// runner harnesses (cotest's `run-joint-e2e.ps1`) get a durable trace they
/// can `tail -f` even when Windows fully buffers stdout under
/// `Start-Process -RedirectStandardOutput`.
///
/// Returns the appender's worker guard. The caller MUST hold it for the
/// process lifetime; dropping it earlier flushes and closes the channel
/// (typical pattern: bind to `_guard` in `main`).
struct TracingGuards {
    _file_guard: Option<tracing_appender::non_blocking::WorkerGuard>,
    _otel_guard: soland::otel::OtelGuard,
}

fn init_tracing(log_format: soland::config::LogFormat) -> anyhow::Result<TracingGuards> {
    use soland::config::LogFormat;
    use tracing_subscriber::{Layer, Registry, fmt};

    let filter = tracing_subscriber::EnvFilter::from_default_env();
    // Stdout writer: structured JSON in production, ANSI-decorated text in
    // development. JSON is required by the runbook log-search recipes; the
    // operator can force either side via `SOLAND_LOG_FORMAT=json|plain`.
    let stdout_layer: Box<dyn Layer<Registry> + Send + Sync> = match log_format {
        LogFormat::Json => Box::new(
            fmt::layer()
                .json()
                .with_current_span(true)
                .with_span_list(false)
                .with_writer(std::io::stdout),
        ),
        LogFormat::Plain => Box::new(fmt::layer().with_writer(std::io::stdout)),
    };
    let mut layers: Vec<Box<dyn Layer<Registry> + Send + Sync>> = vec![stdout_layer];

    let log_file = std::env::var("SOLAND_LOG_FILE")
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());

    let file_guard = if let Some(path) = log_file {
        let path = std::path::PathBuf::from(path);
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).with_context(|| {
                    format!(
                        "failed to create parent directory for SOLAND_LOG_FILE: {}",
                        parent.display()
                    )
                })?;
            }
        }
        let file_name = path
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("SOLAND_LOG_FILE must include a file name"))?
            .to_owned();
        let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
        // `rolling::never` is misnamed: it produces a non-rotating appender
        // that just opens (or creates) the file and appends each event.
        let appender = match dir {
            Some(dir) => tracing_appender::rolling::never(dir, &file_name),
            None => tracing_appender::rolling::never(".", &file_name),
        };
        let (writer, guard) = tracing_appender::non_blocking(appender);
        let file_layer: Box<dyn Layer<Registry> + Send + Sync> = match log_format {
            LogFormat::Json => Box::new(
                fmt::layer()
                    .json()
                    .with_current_span(true)
                    .with_span_list(false)
                    .with_writer(writer),
            ),
            LogFormat::Plain => Box::new(fmt::layer().with_ansi(false).with_writer(writer)),
        };
        layers.push(file_layer);
        Some(guard)
    } else {
        None
    };

    let (otel_guard, otel_layer) = soland::otel::init_layer("soland")?;
    if let Some(layer) = otel_layer {
        layers.push(layer);
    }

    tracing_subscriber::registry()
        .with(layers)
        .with(filter)
        .try_init()
        .map_err(|error| anyhow::anyhow!("tracing init failed: {error}"))?;

    Ok(TracingGuards {
        _file_guard: file_guard,
        _otel_guard: otel_guard,
    })
}

async fn run_server<A>(acceptor: A, state: AppState)
where
    A: Acceptor + Send + 'static,
{
    let server = Server::new(acceptor);
    let handle = server.handle();
    tokio::spawn(async move {
        shutdown_signal().await;
        // `None` means wait until all in-flight requests finish before
        // closing the listener.
        handle.stop_graceful(None);
    });
    server.serve(service(state)).await;
}

/// Resolves once an OS shutdown signal arrives. On Unix this is `SIGINT`
/// (Ctrl-C) or `SIGTERM` (`docker stop`, Kubernetes pod termination, systemd
/// `stop`); on Windows it is the Ctrl-C signal that `cmd.exe`, PowerShell,
/// and the service control manager translate to a console close.
async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(error) = signal::ctrl_c().await {
            tracing::error!(%error, "failed to install Ctrl-C handler");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(mut stream) => {
                stream.recv().await;
            }
            Err(error) => {
                tracing::error!(%error, "failed to install SIGTERM handler");
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            tracing::info!(event = "shutdown_signal", signal = "SIGINT", "shutting down");
        }
        _ = terminate => {
            tracing::info!(event = "shutdown_signal", signal = "SIGTERM", "shutting down");
        }
    }
}

/// P5 (5.5) — container HEALTHCHECK subcommand. Hits the running
/// soland's `/health` endpoint over loopback and exits 0 on success,
/// 1 on any failure. The bind URL is derived from `SOLAND_BIND` (defaults
/// `127.0.0.1:8698`); operators can override per-invocation with
/// `SOLAND_HEALTHCHECK_URL` or by passing `--url <url>` after the
/// subcommand. This eliminates the runtime `curl` dependency the
/// previous Dockerfile relied on (incompatible with distroless bases).
async fn run_healthcheck(args: &[String]) -> anyhow::Result<()> {
    // Allow `soland healthcheck --url https://...` to override the
    // default. The CLI is intentionally trivial — there is no clap
    // dependency on the binary's hot path.
    let url_override = args
        .windows(2)
        .find(|pair| pair[0] == "--url")
        .map(|pair| pair[1].clone());
    let url = url_override
        .or_else(|| std::env::var("SOLAND_HEALTHCHECK_URL").ok())
        .unwrap_or_else(|| {
            let bind = std::env::var("SOLAND_BIND").unwrap_or_else(|_| "127.0.0.1:8698".to_owned());
            // SOLAND_BIND uses a `host:port` shape — assume plain HTTP on
            // loopback, which matches the in-container HEALTHCHECK call
            // pattern (TLS termination lives at the reverse proxy).
            format!("http://{bind}/health")
        });

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    match client.get(&url).send().await {
        Ok(resp) if resp.status().is_success() => {
            eprintln!("soland healthcheck OK: {url} → {}", resp.status());
            Ok(())
        }
        Ok(resp) => {
            eprintln!(
                "soland healthcheck FAIL: {url} → {} (non-success)",
                resp.status()
            );
            std::process::exit(1);
        }
        Err(err) => {
            eprintln!("soland healthcheck FAIL: {url} → {err}");
            std::process::exit(1);
        }
    }
}
