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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // Fail fast at startup if a bundled Contrix artifact is malformed instead
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
        match soland::state::did_resolver_chain::probe_webvh_provider_describe(
            &url,
            std::time::Duration::from_secs(3),
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
    let state = AppState::new(config.clone(), Db::from_env()?);

    // Spawn the multisig leader-election watchdog. The task wakes every
    // 30s by default, scans `multisig_pending` for rows
    // whose threshold is met + canonical_b64 is non-empty, claims an
    // unleased row, and aggregates via SDK `ThresholdAggregator`. Returns
    // a JoinHandle we drop on the floor — the task lives for the process
    // lifetime and shutdown_signal teardown closes the runtime.
    let watchdog_config = MultisigWatchdogConfig::for_service(&state.config.service_did);
    let _watchdog = MultisigWatchdog::new(state.clone(), watchdog_config).spawn();

    // MAL-11 compaction prune walk worker. No-op when
    // `SOLAND_COMPACTION_PRUNE_WALK_INTERVAL_SECS=0` (the default) — the
    // explicit `POST /api/admin/v1/spaces/{space_id}/anchor-dag/prune`
    // endpoint stays operator-driven. Set the env var to enable periodic
    // walking; see `compactor.rs` for the policy and "when to enable"
    // rationale.
    let _compactor = soland::compactor::spawn(state.clone());

    tracing::info!(
        bind = %config.bind,
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
        tracing::info!("TLS listener enabled with rustls");
        run_server(acceptor, state).await;
    } else {
        let acceptor = TcpListener::new(config.bind.to_string()).bind().await;
        run_server(acceptor, state).await;
    }
    tracing::info!("soland stopped");
    Ok(())
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
            tracing::info!("received SIGINT, shutting down");
        }
        _ = terminate => {
            tracing::info!("received SIGTERM, shutting down");
        }
    }
}
