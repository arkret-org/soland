use anyhow::Context;
use salvo::conn::Acceptor;
use salvo::conn::rustls::{Keycert, RustlsConfig};
use salvo::prelude::*;
use soland_http::config::{AppConfig, StartupOverrides};
use soland_http::multisig_watchdog::{MultisigWatchdog, MultisigWatchdogConfig};
use soland_http::service;
use soland_http::state::AppState;
use soland_services::validate_embedded_artifacts;
use soland_storage_postgres::Db;
use tokio::signal;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

pub(crate) mod bootstrap;
pub(crate) mod object_storage;
pub(crate) mod otel;
pub(crate) mod runtime;

fn main() -> anyhow::Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run())
}

async fn run() -> anyhow::Result<()> {
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

    // Configuration comes first: the subscriber, the exporter and everything
    // after all read `AppConfig`, so there is one parse of every value.
    // Logging deliberately does not precede this. A configuration failure
    // means the process does not start, and that error returns from `main` for
    // the runtime to print — there is nothing for a subscriber to add. Before
    // this order, `SOLAND_DEVELOPMENT_MODE` was parsed a second time here with
    // a case-sensitive matcher that did not accept `on`, so
    // `SOLAND_DEVELOPMENT_MODE=on` produced a development-mode server writing
    // production logs.
    let values = soland::process_config::load(&raw_args)?;
    let mut config = AppConfig::from_values(
        &values,
        StartupOverrides {
            bind: arg_value(&raw_args, "--bind"),
            first_provisioning: raw_args.iter().any(|arg| arg == "--first-provisioning"),
        },
    )?;

    // Keep this guard alive for the process lifetime so the non-blocking
    // file appender drains its channel on shutdown. Dropping the guard
    // flushes pending writes; storing it in `_file_guard` defers that drop
    // until `main` returns.
    let _tracing_guards = init_tracing(&config)?;

    // Fail fast at startup if a bundled Arkret artifact is malformed, or if the
    // Draft 2020-12 schema catalog does not compile as a whole, instead of
    // crashing the first request that touches the offending OnceLock or Event.
    if let Err(error) = validate_embedded_artifacts() {
        tracing::error!(
            artifact = error.label,
            detail = %error.detail,
            spec_artifacts_dir = ?soland_services::protocol_artifacts::spec_artifacts_dir(),
            "startup artifact gate failed; refusing to serve protocol traffic"
        );
        return Err(error.into());
    }
    tracing::info!(
        spec_artifacts_dir = ?soland_services::protocol_artifacts::spec_artifacts_dir(),
        "protocol schema catalog compiled at startup"
    );

    // Connect the database and resolve this deployment's own service identity
    // before anything derived from it is constructed. The DID remains runtime
    // state; only the derived trust-domain value is copied into operational
    // config for existing policy consumers.
    let db = Db::connect(
        config.database_url.as_deref(),
        soland_storage_postgres::PoolTuning {
            max_size: config.db_pool_max_size,
            acquire_timeout_seconds: config.db_pool_acquire_timeout_seconds,
        },
    )
    .await?;
    // Fail fast before anything is accepted: an outbound-federating deployment
    // on the in-memory outbox would silently drop pending deliveries on every
    // restart (`sync/federation.md` §4.1).
    soland_http::config::assert_durable_outbox_backend(&config, db.pool.is_some())?;
    let bootstrap = crate::bootstrap::resolve_and_build_persistence(&config, &db).await?;
    let bootstrap = if matches!(
        bootstrap.state,
        arkret_identity::service_identity::DidCoreIdentityState::WaitingProvider { .. }
    ) {
        tracing::warn!(
            retry_seconds = 5,
            "service identity Provider is unavailable; serving fail-closed health endpoints while retrying"
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
            wait_for_service_identity(acceptor, config.clone(), bootstrap).await?
        } else {
            let acceptor = TcpListener::new(config.bind.to_string()).bind().await;
            wait_for_service_identity(acceptor, config.clone(), bootstrap).await?
        }
    } else {
        bootstrap
    };
    let _service_id = bootstrap
        .state
        .identity()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "service identity bootstrap did not produce a serving identity: {:?}",
                bootstrap.state
            )
        })?
        .service_id
        .to_string();
    // Probe the optional external webvh provider before advertising it as
    // active. The configured URL remains visible in `/identity/describe` even
    // when the probe fails so coauth can show the operator's intended setup.
    if let Some(url) = config.external_webvh_provider_url.clone() {
        let expected_trust_domain = config
            .external_webvh_provider_trust_domain
            .clone()
            .unwrap_or_else(|| config.trust_domain.to_string());
        match soland_http::state::did_resolver_chain::probe_webvh_provider_describe(
            &url,
            std::time::Duration::from_secs(3),
            None,
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
    let supervisor_persistence = bootstrap.persistence.clone();
    let supervisor_key_store = bootstrap.key_store.clone();
    let resolution_commitment = bootstrap
        .resolution_commitment
        .clone()
        .ok_or_else(|| anyhow::anyhow!("serving service identity has no resolution commitment"))?;
    let state = crate::runtime::build_app_state(
        config.clone(),
        db,
        bootstrap.persistence,
        bootstrap.state,
        resolution_commitment,
        bootstrap.signing_seed,
    )?;
    spawn_service_identity_supervisor(state.clone(), supervisor_persistence, supervisor_key_store);
    // Finish boot: seed demo data + hydrate the Realm directory and
    // projections from the (now async) persistence store.
    state.hydrate().await?;
    spawn_federation_peer_discovery(state.clone());

    // G3.S9 — sovereign enclave profile invariants. When
    // `SOLAND_SOVEREIGN_ENCLAVE=1` the configured posture MUST satisfy:
    //   * federation_outbound_enabled = false
    //   * did_resolver_allow_methods non-empty
    // Fail fast at startup if either invariant is violated; the enclave
    // profile claim on `/server/describe` would otherwise be a lie.
    let enclave_assertion =
        soland_http::routing::extensions::sovereign::assert_enclave_invariants(state.config());
    if !enclave_assertion.is_compliant() {
        anyhow::bail!(
            "SOLAND_SOVEREIGN_ENCLAVE=1 but enclave invariants are not satisfied: {}",
            enclave_assertion.violations.join("; ")
        );
    }
    if enclave_assertion.enabled {
        tracing::info!(
            target: "sovereign_boundary_audit",
            allowed_outbound_hosts = ?state.config().sovereign_enclave_allowed_outbound_hosts,
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
    let watchdog_config = MultisigWatchdogConfig::for_service(state.service_id());
    let _watchdog = MultisigWatchdog::new(state.clone(), watchdog_config).spawn();
    tracing::info!(
        worker = "multisig_watchdog",
        enabled = true,
        service_id = %state.service_id(),
        "background worker configured"
    );

    let _control_seal_coordinator = soland_http::control_seal_coordinator::spawn(state.clone());
    tracing::info!(
        worker = "control_seal_coordinator",
        enabled = true,
        service_id = %state.service_id(),
        "background worker configured"
    );

    let _account_erasure_worker = soland_http::account_erasure_worker::spawn(state.clone());
    tracing::info!(
        worker = "account_erasure",
        enabled = true,
        service_id = %state.service_id(),
        "background worker configured"
    );

    // account-lifecycle.md §7.1 — retries the push-gateway deactivation
    // fanout until the gateway acks, keeping `deactivation_partial` honest.
    // `None` when no gateway is configured (single-box posture: the local
    // push-route purge completes the Push-route fanout row).
    let _deactivation_push_fanout_worker =
        soland_http::deactivation_push_fanout::spawn(state.clone());
    tracing::info!(
        worker = "deactivation_push_fanout",
        enabled = _deactivation_push_fanout_worker.is_some(),
        "background worker configured"
    );

    let _service_route_handover_audience_worker =
        soland_http::service_route_handover_reconciler::spawn(state.clone());
    tracing::info!(
        worker = "service_route_handover_audience",
        enabled = true,
        "background worker configured"
    );

    // TTL backstop for the durable sync-cursor handle table (forward-progress
    // pruning on cursor presentation handles the steady state; this clears
    // rows whose client never returned).
    let _sync_cursor_ttl_sweeper =
        soland_http::routing::spawn_sync_cursor_ttl_sweeper(state.clone());
    tracing::info!(
        worker = "sync_cursor_ttl_sweep",
        "background worker configured"
    );

    // GC for expired incomplete resumable (tus) blob upload parts — spec
    // media-and-blob.md §2.1: incomplete parts have a bounded lifetime and
    // never produce a referencable blob_ref.
    let _resumable_upload_ttl_sweeper =
        soland_http::routing::spawn_resumable_upload_ttl_sweeper(state.clone());
    tracing::info!(
        worker = "resumable_upload_ttl_sweep",
        "background worker configured"
    );

    let _history_request_replica_reconciler =
        soland_http::routing::spawn_history_request_replica_reconciler(state.clone());
    tracing::info!(
        worker = "history_request_replica_reconcile",
        "background worker configured"
    );

    // G3.S0 — durable outbound federation HTTP delivery worker. No-op
    // when `SOLAND_FEDERATION_OUTBOUND=0` (used by integration tests
    // that don't want background HTTP traffic). The dispatcher drains
    // the `federation_outbox` table populated by
    // `routing::federation::federation::broadcast_*_to_peers`.
    let _federation_dispatcher = soland_http::routing::federation::outbox::spawn(state.clone());
    tracing::info!(
        worker = "federation_outbox",
        enabled = state.config().federation_outbound_enabled,
        "background worker configured"
    );
    let _federation_frontier_exchange =
        soland_http::routing::federation::frontier_exchange::spawn(state.clone());
    tracing::info!(
        worker = "federation_frontier_exchange",
        enabled = state.config().federation_outbound_enabled,
        "background worker configured"
    );
    let _rrk_acquisition = soland_http::routing::federation::rrk_acquisition::spawn(state.clone());
    tracing::info!(
        worker = "rrk_acquisition",
        enabled = _rrk_acquisition.is_some(),
        "background worker configured"
    );

    let _metrics_server =
        soland_http::metrics::spawn_metrics_server(state.clone(), config.metrics_bind).await?;
    tracing::info!(
        worker = "metrics_server",
        bind = %config.metrics_bind,
        "background worker configured"
    );

    tracing::info!(
        bind = %config.bind,
        metrics_bind = %config.metrics_bind,
        public_base_url = %config.public_base_url,
        service_id = %state.service_id(),
        tls_enabled = config.tls_enabled(),
        tls_cert_path = ?config.tls_cert_path,
        tls_key_path = ?config.tls_key_path,
        embedded_webvh_provider_enabled = config.embedded_webvh_provider_enabled,
        external_webvh_provider_url = ?config.external_webvh_provider_url,
        object_storage_backend = %config.object_storage.backend_name(),
        object_storage_target = %config.object_storage.log_target(),
        development_mode = config.development_mode,
        storage = state.storage_mode(),
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

fn arg_value(args: &[String], name: &str) -> Option<String> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == name {
            return iter.next().cloned();
        }
        if let Some(value) = arg.strip_prefix(&format!("{name}=")) {
            return Some(value.to_owned());
        }
    }
    None
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
    _otel_guard: crate::otel::OtelGuard,
}

fn init_tracing(config: &AppConfig) -> anyhow::Result<TracingGuards> {
    let log_format = config.log_format;
    let development_mode = config.development_mode;
    use soland_http::config::LogFormat;
    use tracing_subscriber::{Layer, Registry, fmt};

    let filter = match config.log_filter.as_deref() {
        Some(directive) => tracing_subscriber::EnvFilter::new(directive),
        None if development_mode => tracing_subscriber::EnvFilter::new("debug"),
        None => tracing_subscriber::EnvFilter::new(""),
    };
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

    let log_file = config.log_file.clone();

    let file_guard = if let Some(path) = log_file {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create parent directory for SOLAND_LOG_FILE: {}",
                    parent.display()
                )
            })?;
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

    let (otel_guard, otel_layer) = crate::otel::init_layer(&config.otel, "soland")?;
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

/// Drain window used when `SOLAND_SHUTDOWN_GRACE_SECS` is unset. The request
/// grace stays "wait indefinitely" in that case, but a drained peer still needs
/// a deadline it can plan its checkpoint against.
const DEFAULT_CONNECTION_DRAIN_GRACE: std::time::Duration = std::time::Duration::from_secs(10);

async fn run_server<A>(acceptor: A, state: AppState)
where
    A: Acceptor + Send + 'static,
{
    let server = Server::new(acceptor);
    let handle = server.handle();
    // Bounded drain: after a shutdown signal, stop accepting and wait up to
    // `SOLAND_SHUTDOWN_GRACE_SECS` for in-flight requests to finish before
    // forcibly closing the listener. Unset (or 0) preserves the previous
    // "wait indefinitely" behavior. A finite bound matters under an
    // orchestrator (Kubernetes / systemd) that will SIGKILL after its own
    // grace period — a long-lived `events.subscribe` stream would otherwise
    // block a clean shutdown until the hard kill.
    let shutdown_grace = state
        .config()
        .shutdown_grace_seconds
        .map(std::time::Duration::from_secs);
    // Long-lived transports get an explicit drain notice before the listener
    // stops, so peers checkpoint and reconnect instead of discovering the
    // shutdown as a dropped socket. The notice needs a finite deadline even
    // when the request grace is "wait indefinitely".
    let drain_grace = shutdown_grace.unwrap_or(DEFAULT_CONNECTION_DRAIN_GRACE);
    let drain_state = state.clone();
    tokio::spawn(async move {
        shutdown_signal().await;
        drain_state.begin_connection_drain(drain_grace);
        handle.stop_graceful(shutdown_grace);
    });
    server.serve(service(state)).await;
}

async fn wait_for_service_identity<A>(
    acceptor: A,
    config: AppConfig,
    bootstrap: crate::bootstrap::ServiceIdentityBootstrap,
) -> anyhow::Result<crate::bootstrap::ServiceIdentityBootstrap>
where
    A: Acceptor + Send + 'static,
{
    let persistence = bootstrap.persistence;
    let key_store = bootstrap.key_store;
    let server = Server::new(acceptor);
    let handle = server.handle();
    let server_task = tokio::spawn(async move {
        server.serve(waiting_service()).await;
    });
    let resolve = async {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            match crate::bootstrap::retry_service_identity(
                &config,
                persistence.clone(),
                key_store.clone(),
            )
            .await
            {
                Ok(bootstrap) if bootstrap.state.identity().is_some() => break Ok(bootstrap),
                Ok(bootstrap)
                    if matches!(
                        bootstrap.state,
                        arkret_identity::service_identity::DidCoreIdentityState::WaitingProvider { .. }
                    ) =>
                {
                    tracing::warn!("service identity Provider remains unavailable; retrying");
                }
                Ok(bootstrap) => {
                    break Err(anyhow::anyhow!(
                        "service identity cannot become ready: {:?}",
                        bootstrap.state
                    ));
                }
                Err(error) => {
                    tracing::error!(%error, "service identity retry failed; retaining waiting state");
                }
            }
        }
    };
    let result = tokio::select! {
        result = resolve => result,
        _ = shutdown_signal() => Err(anyhow::anyhow!("shutdown requested while waiting for service identity Provider")),
    };
    handle.stop_graceful(Some(std::time::Duration::from_secs(2)));
    let _ = server_task.await;
    result
}

fn waiting_service() -> Service {
    Service::new(
        Router::new()
            .push(Router::with_path("health").get(service_identity_waiting))
            .push(Router::with_path("readyz").get(service_identity_waiting))
            .push(Router::with_path("_arkret/describe").get(service_identity_waiting)),
    )
}

#[handler]
async fn service_identity_waiting(res: &mut Response) {
    res.status_code(StatusCode::SERVICE_UNAVAILABLE);
    res.headers_mut().insert(
        salvo::http::header::RETRY_AFTER,
        salvo::http::HeaderValue::from_static("5"),
    );
    res.render(Json(serde_json::json!({
        "ok": false,
        "errcode": "service_identity_unavailable",
        "error": "service identity Provider is temporarily unavailable",
        "service_identity": {
            "state": "waiting_provider",
            "service_id": null,
            "retry_after_seconds": 5
        }
    })));
}

fn spawn_service_identity_supervisor(
    state: AppState,
    persistence: soland_services::persistence::PersistenceHandle,
    key_store: Option<std::sync::Arc<dyn arkret_keystore::KeyStore>>,
) {
    if !matches!(
        state.service_identity_state().as_ref(),
        arkret_identity::service_identity::DidCoreIdentityState::DegradedStored { .. }
    ) {
        return;
    }
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            match crate::bootstrap::retry_service_identity(
                state.config(),
                persistence.clone(),
                key_store.clone(),
            )
            .await
            {
                Ok(bootstrap) => {
                    let keep_retrying = matches!(
                        bootstrap.state,
                        arkret_identity::service_identity::DidCoreIdentityState::DegradedStored { .. }
                            | arkret_identity::service_identity::DidCoreIdentityState::WaitingProvider { .. }
                    );
                    if let Some(identity) = bootstrap.state.identity()
                        && identity.service_id.as_str() != state.service_id()
                    {
                        tracing::error!(
                            runtime_service_id = %state.service_id(),
                            provider_service_id = %identity.service_id,
                            "service identity supervisor rejected a runtime identity switch"
                        );
                        break;
                    }
                    if let Some(commitment) = bootstrap.resolution_commitment {
                        state.replace_service_resolution_commitment(commitment);
                    }
                    state.replace_service_identity_state(bootstrap.state);
                    if !keep_retrying {
                        break;
                    }
                }
                Err(error) => {
                    tracing::error!(%error, "service identity supervisor retry failed");
                }
            }
        }
    });
}

/// Resolve federation peers through the standard service describe and DID
/// document operations. Runtime settings retain the discovered DID and the
/// in-memory verifier retains its endpoint-bound assertion key; boot
/// configuration remains free of copied identities and public-key pins.
fn spawn_federation_peer_discovery(state: AppState) {
    tokio::spawn(async move {
        let initial_retry = std::time::Duration::from_millis(250);
        let max_retry = std::time::Duration::from_secs(5);
        let mut retry_delay = initial_retry;
        loop {
            tokio::time::sleep(retry_delay).await;
            let peers = state
                .settings()
                .federation_peers
                .iter()
                .filter_map(|entry| {
                    federation_peer_endpoint(entry).map(|endpoint| (entry.clone(), endpoint))
                })
                .collect::<Vec<_>>();
            if peers.is_empty() {
                retry_delay = max_retry;
                continue;
            }

            let mut resolved = std::collections::HashMap::new();
            for (configured, endpoint) in peers {
                let base_url = match url::Url::parse(endpoint.as_str()) {
                    Ok(base_url) => base_url,
                    Err(error) => {
                        tracing::warn!(%endpoint, %error, "invalid federation peer endpoint");
                        continue;
                    }
                };
                let client = match arkret_http_client::ClientBuilder::new(base_url)
                    .allow_insecure_localhost()
                    .build()
                {
                    Ok(client) => client,
                    Err(error) => {
                        tracing::warn!(%endpoint, %error, "invalid federation peer endpoint");
                        continue;
                    }
                };
                match client.describe().await {
                    Ok(description)
                        if description.service_kind
                            == arkret_wire::ServiceKind::PrincipalServer
                            && description.service_id.as_str() != state.service_id() =>
                    {
                        let document_view = match client
                            .identity_document(
                                description.service_resolution.full_id.as_str(),
                                None,
                            )
                            .await
                        {
                            Ok(document) => document,
                            Err(error) => {
                                tracing::debug!(
                                    %endpoint,
                                    peer_service_id = %description.service_id,
                                    %error,
                                    "federation peer DID document is not ready; retrying"
                                );
                                continue;
                            }
                        };
                        let document_value = serde_json::Value::Object(
                            document_view.did_document.into_iter().collect(),
                        );
                        let document = match serde_json::from_value::<
                            arkret_models_identity::service_identity::ServiceDidDocument,
                        >(document_value)
                        {
                            Ok(document) => document,
                            Err(error) => {
                                tracing::warn!(
                                    %endpoint,
                                    peer_service_id = %description.service_id,
                                    %error,
                                    "federation peer returned an invalid service DID document"
                                );
                                continue;
                            }
                        };
                        let public_base = match arkret_models_identity::service_identity::CanonicalServiceUrl::canonicalize(
                            endpoint.as_str(),
                        ) {
                            Ok(public_base) => public_base,
                            Err(error) => {
                                tracing::warn!(%endpoint, %error, "invalid federation peer endpoint");
                                continue;
                            }
                        };
                        let registration_key = match arkret_models_identity::service_identity::ServiceRegistrationKey::new(
                            arkret_wire::ServiceKind::PrincipalServer,
                            public_base,
                        ) {
                            Ok(key) => key,
                            Err(error) => {
                                tracing::warn!(%endpoint, %error, "invalid federation peer registration key");
                                continue;
                            }
                        };
                        let expected_verification_method =
                            soland_http::routing::federation::federation_service_signature_key_id(
                                description.service_resolution.full_id.as_str(),
                            );
                        let receipt_verification_method =
                            format!("{}#notary-key", description.service_resolution.full_id);
                        if document.id != description.service_resolution.full_id
                            || document.validate_for(&registration_key).is_err()
                            || !document
                                .assertion_method
                                .iter()
                                .any(|method| method == &expected_verification_method)
                            || !document
                                .assertion_method
                                .iter()
                                .any(|method| method == &receipt_verification_method)
                        {
                            tracing::warn!(
                                %endpoint,
                                peer_service_id = %description.service_id,
                                "federation peer DID document does not bind the described Principal Server identity"
                            );
                            continue;
                        }
                        let Some(public_key_multibase) = document
                            .verification_method
                            .iter()
                            .find(|method| method.id == expected_verification_method)
                            .map(|method| method.public_key_multibase.as_str())
                        else {
                            tracing::warn!(
                                %endpoint,
                                peer_service_id = %description.service_id,
                                "federation peer DID document has no active assertion key"
                            );
                            continue;
                        };
                        let Some(receipt_public_key_multibase) = document
                            .verification_method
                            .iter()
                            .find(|method| method.id == receipt_verification_method)
                            .map(|method| method.public_key_multibase.as_str())
                        else {
                            tracing::warn!(
                                %endpoint,
                                peer_service_id = %description.service_id,
                                "federation peer DID document has no active receipt assertion key"
                            );
                            continue;
                        };
                        let verifying_key =
                            match arkret_canonical::decode_ed25519_multibase(public_key_multibase)
                                .map_err(|error| error.to_string())
                                .and_then(|raw| {
                                    ed25519_dalek::VerifyingKey::from_bytes(&raw)
                                        .map_err(|error| error.to_string())
                                }) {
                                Ok(key) => key,
                                Err(error) => {
                                    tracing::warn!(
                                        %endpoint,
                                        peer_service_id = %description.service_id,
                                        %error,
                                        "federation peer assertion key is invalid"
                                    );
                                    continue;
                                }
                            };
                        let receipt_verifying_key =
                            match arkret_canonical::decode_ed25519_multibase(
                                receipt_public_key_multibase,
                            )
                            .map_err(|error| error.to_string())
                            .and_then(|raw| {
                                ed25519_dalek::VerifyingKey::from_bytes(&raw)
                                    .map_err(|error| error.to_string())
                            }) {
                                Ok(key) => key,
                                Err(error) => {
                                    tracing::warn!(
                                        %endpoint,
                                        peer_service_id = %description.service_id,
                                        %error,
                                        "federation peer receipt assertion key is invalid"
                                    );
                                    continue;
                                }
                            };
                        let discovered = format!(
                            "{}|{}|{}",
                            endpoint.trim_end_matches('/'),
                            description.service_id,
                            description.trust_domain,
                        );
                        let previous_service_id = federation_peer_service_id(&configured);
                        let key_changed = state
                            .federation_peer_verifying_key(description.service_id.as_str())
                            .as_ref()
                            != Some(&verifying_key);
                        state.install_federation_peer_verifying_key(
                            previous_service_id.as_deref(),
                            description.service_id.as_str(),
                            verifying_key,
                        );
                        let previous_receipt_verification_method = previous_service_id
                            .as_ref()
                            .map(|service_id| format!("{service_id}#notary-key"));
                        state.install_federation_peer_verification_method_key(
                            previous_receipt_verification_method.as_deref(),
                            &receipt_verification_method,
                            receipt_verifying_key,
                        );
                        if configured != discovered || key_changed {
                            tracing::info!(
                                peer_endpoint = %endpoint,
                                peer_service_id = %description.service_id,
                                peer_verification_method = %expected_verification_method,
                                "resolved federation peer service identity and assertion key"
                            );
                        }
                        resolved.insert(configured, discovered);
                    }
                    Ok(description) => {
                        tracing::warn!(
                            peer_endpoint = %endpoint,
                            peer_service_kind = %description.service_kind.as_str(),
                            peer_service_id = %description.service_id,
                            "federation peer describe returned an ineligible service"
                        );
                    }
                    Err(error) => {
                        tracing::debug!(%endpoint, %error, "federation peer identity is not ready; retrying");
                    }
                }
            }
            if resolved.is_empty() {
                retry_delay = retry_delay.saturating_mul(2).min(max_retry);
                continue;
            }
            state.apply_resolved_federation_peers(&resolved);
            retry_delay = max_retry;
        }
    });
}

fn federation_peer_endpoint(entry: &str) -> Option<String> {
    let entry = entry.trim();
    if entry.is_empty() {
        return None;
    }
    let (left, right) = entry
        .split_once('|')
        .map(|(left, right)| (left.trim(), right.trim()))
        .unwrap_or((entry, entry));
    [left, right]
        .into_iter()
        .find(|candidate| candidate.starts_with("https://") || candidate.starts_with("http://"))
        .map(|endpoint| endpoint.trim_end_matches('/').to_owned())
}

fn federation_peer_service_id(entry: &str) -> Option<String> {
    entry
        .split('|')
        .map(str::trim)
        .find(|candidate| arkret_identifiers::DidCoreId::new((*candidate).to_owned()).is_ok())
        .map(ToOwned::to_owned)
}

#[cfg(test)]
fn unresolved_federation_peer_endpoint(entry: &str) -> Option<String> {
    if federation_peer_service_id(entry).is_some() {
        return None;
    }
    federation_peer_endpoint(entry)
}

#[cfg(test)]
#[expect(
    clippy::items_after_test_module,
    reason = "discovery tests stay adjacent to their private parser helpers"
)]
mod federation_peer_discovery_tests {
    use super::{federation_peer_endpoint, unresolved_federation_peer_endpoint};

    #[test]
    fn endpoint_only_peer_requires_runtime_discovery() {
        assert_eq!(
            unresolved_federation_peer_endpoint("https://peer.example/"),
            Some("https://peer.example".to_owned())
        );
        assert_eq!(
            unresolved_federation_peer_endpoint("https://peer.example|ak:did_core:webvh:zPeer"),
            None
        );
        assert_eq!(
            federation_peer_endpoint("https://peer.example|ak:did_core:webvh:zPeer"),
            Some("https://peer.example".to_owned())
        );
    }
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
