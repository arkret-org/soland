use anyhow::Context;
use salvo::conn::Acceptor;
use salvo::conn::rustls::{Keycert, RustlsConfig};
use salvo::prelude::*;
use soland::config::AppConfig;
use soland::multisig_watchdog::{MultisigWatchdog, MultisigWatchdogConfig};
use soland::state::AppState;
use soland::{artifacts, service};
use soland_data::Db;
use tokio::signal;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

fn main() -> anyhow::Result<()> {
    soland::config::prepare_process_environment()?;
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

    // Fail fast at startup if a bundled Arkret artifact is malformed instead
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
    // Connect the database and resolve this deployment's own service identity
    // before anything derived from it is constructed. The DID remains runtime
    // state; only the derived trust-domain value is copied into operational
    // config for existing policy consumers.
    let db = Db::from_env().await?;
    let bootstrap = soland::bootstrap::resolve_and_build_persistence(&config, &db).await?;
    let bootstrap = if matches!(
        bootstrap.state,
        arkret_sdk::ServiceIdentityState::WaitingProvider { .. }
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
    let service_id = bootstrap
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
    config.trust_domain = soland::config::derive_trust_domain(&service_id)?;
    // Probe the optional external webvh provider before advertising it as
    // active. The configured URL remains visible in `/identity/describe` even
    // when the probe fails so coauth can show the operator's intended setup.
    if let Some(url) = config.external_webvh_provider_url.clone() {
        let expected_trust_domain = std::env::var("SOLAND_EXTERNAL_WEBVH_PROVIDER_TRUST_DOMAIN")
            .ok()
            .unwrap_or_else(|| config.trust_domain.clone());
        match soland::state::did_resolver_chain::probe_webvh_provider_describe(
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
    let state = AppState::new_with_service_identity(
        config.clone(),
        db,
        bootstrap.persistence,
        bootstrap.state,
        bootstrap.signing_seed,
    );
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
    let watchdog_config = MultisigWatchdogConfig::for_service(&state.service_id);
    let _watchdog = MultisigWatchdog::new(state.clone(), watchdog_config).spawn();
    tracing::info!(
        worker = "multisig_watchdog",
        enabled = true,
        service_id = %state.service_id,
        "background worker configured"
    );

    // MAL-11 compaction prune walk worker. No-op when
    // `SOLAND_COMPACTION_PRUNE_WALK_INTERVAL_SECS=0` (the default) — the
    // explicit `POST /_soland/admin/realms/{realm_id}/seal-dag/prune`
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

    // TTL backstop for the durable sync-cursor handle table (forward-progress
    // pruning on cursor presentation handles the steady state; this clears
    // rows whose client never returned).
    let _sync_cursor_ttl_sweeper = soland::routing::spawn_sync_cursor_ttl_sweeper(state.clone());
    tracing::info!(
        worker = "sync_cursor_ttl_sweep",
        "background worker configured"
    );

    // GC for expired incomplete resumable (tus) blob upload parts — spec
    // media-and-blob.md §2.1: incomplete parts have a bounded lifetime and
    // never produce a referencable blob_ref.
    let _resumable_upload_ttl_sweeper =
        soland::routing::spawn_resumable_upload_ttl_sweeper(state.clone());
    tracing::info!(
        worker = "resumable_upload_ttl_sweep",
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
    let _federation_frontier_exchange =
        soland::routing::federation::frontier_exchange::spawn(state.clone());
    tracing::info!(
        worker = "federation_frontier_exchange",
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
        service_id = %state.service_id,
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
    // Bounded drain: after a shutdown signal, stop accepting and wait up to
    // `SOLAND_SHUTDOWN_GRACE_SECS` for in-flight requests to finish before
    // forcibly closing the listener. Unset (or 0) preserves the previous
    // "wait indefinitely" behavior. A finite bound matters under an
    // orchestrator (Kubernetes / systemd) that will SIGKILL after its own
    // grace period — a long-lived `events.subscribe` stream would otherwise
    // block a clean shutdown until the hard kill.
    let shutdown_grace = std::env::var("SOLAND_SHUTDOWN_GRACE_SECS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|secs| *secs > 0)
        .map(std::time::Duration::from_secs);
    tokio::spawn(async move {
        shutdown_signal().await;
        handle.stop_graceful(shutdown_grace);
    });
    server.serve(service(state)).await;
}

async fn wait_for_service_identity<A>(
    acceptor: A,
    config: AppConfig,
    bootstrap: soland::bootstrap::ServiceIdentityBootstrap,
) -> anyhow::Result<soland::bootstrap::ServiceIdentityBootstrap>
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
            match soland::bootstrap::retry_service_identity(
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
                        arkret_sdk::ServiceIdentityState::WaitingProvider { .. }
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
    persistence: std::sync::Arc<dyn soland::persistence::PersistenceStore>,
    key_store: Option<std::sync::Arc<dyn arkret_sdk::KeyStore>>,
) {
    if !matches!(
        state.service_identity_state().as_ref(),
        arkret_sdk::ServiceIdentityState::DegradedStored { .. }
    ) {
        return;
    }
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            match soland::bootstrap::retry_service_identity(
                &state.config,
                persistence.clone(),
                key_store.clone(),
            )
            .await
            {
                Ok(bootstrap) => {
                    let keep_retrying = matches!(
                        bootstrap.state,
                        arkret_sdk::ServiceIdentityState::DegradedStored { .. }
                            | arkret_sdk::ServiceIdentityState::WaitingProvider { .. }
                    );
                    if let Some(identity) = bootstrap.state.identity()
                        && identity.service_id.as_str() != state.service_id
                    {
                        tracing::error!(
                            runtime_service_id = %state.service_id,
                            provider_service_id = %identity.service_id,
                            "service identity supervisor rejected a runtime identity switch"
                        );
                        break;
                    }
                    state
                        .service_identity
                        .store(std::sync::Arc::new(bootstrap.state));
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
                let client = match arkret_sdk::ClientBuilder::new(base_url)
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
                        if description.service_type == arkret_sdk::ServiceType::PrincipalServer
                            && description.service_id.as_str() != state.service_id =>
                    {
                        let document_view = match client
                            .identity_document(description.service_id.as_str(), None)
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
                        let document = match serde_json::from_value::<arkret_sdk::ServiceDidDocument>(
                            document_value,
                        ) {
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
                        let public_base = match arkret_sdk::CanonicalServiceUrl::canonicalize(
                            endpoint.as_str(),
                        ) {
                            Ok(public_base) => public_base,
                            Err(error) => {
                                tracing::warn!(%endpoint, %error, "invalid federation peer endpoint");
                                continue;
                            }
                        };
                        let registration_key = match arkret_sdk::ServiceRegistrationKey::new(
                            arkret_sdk::ServiceType::PrincipalServer,
                            public_base,
                        ) {
                            Ok(key) => key,
                            Err(error) => {
                                tracing::warn!(%endpoint, %error, "invalid federation peer registration key");
                                continue;
                            }
                        };
                        let expected_verification_method =
                            soland::routing::federation::federation_service_signature_key_id(
                                description.service_id.as_str(),
                            );
                        if document.id != description.service_id
                            || document.validate_for(&registration_key).is_err()
                            || !document
                                .assertion_method
                                .iter()
                                .any(|method| method == &expected_verification_method)
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
                        let verifying_key =
                            match arkret_sdk::decode_ed25519_multibase(public_key_multibase)
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
                        let discovered = format!(
                            "{}|{}",
                            endpoint.trim_end_matches('/'),
                            description.service_id
                        );
                        let previous_service_id = federation_peer_service_id(&configured);
                        let key_changed = state
                            .federation_peer_verifying_key(description.service_id.as_str())
                            .as_ref()
                            != Some(&verifying_key);
                        state.federation_peer_verifying_keys.rcu(|current| {
                            let mut next = (**current).clone();
                            if let Some(previous_service_id) = previous_service_id.as_deref()
                                && previous_service_id != description.service_id.as_str()
                            {
                                next.remove(previous_service_id);
                            }
                            next.insert(description.service_id.to_string(), verifying_key);
                            std::sync::Arc::new(next)
                        });
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
                            peer_service_type = %description.service_type.as_str(),
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
            state.settings.rcu(|current| {
                let mut next = (**current).clone();
                for entry in &mut next.federation_peers {
                    if let Some(discovered) = resolved.get(entry) {
                        *entry = discovered.clone();
                    }
                }
                std::sync::Arc::new(next)
            });
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
        .find(|candidate| candidate.starts_with("did:"))
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
mod federation_peer_discovery_tests {
    use super::{federation_peer_endpoint, unresolved_federation_peer_endpoint};

    #[test]
    fn endpoint_only_peer_requires_runtime_discovery() {
        assert_eq!(
            unresolved_federation_peer_endpoint("https://peer.example/"),
            Some("https://peer.example".to_owned())
        );
        assert_eq!(
            unresolved_federation_peer_endpoint(
                "https://peer.example|did:webvh:zPeer:peer.example:webvh:service"
            ),
            None
        );
        assert_eq!(
            federation_peer_endpoint(
                "https://peer.example|did:webvh:zPeer:peer.example:webvh:service"
            ),
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
