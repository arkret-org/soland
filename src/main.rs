use salvo::prelude::*;
use soland::{
    artifacts, config::AppConfig, db::Db,
    multisig_watchdog::{MultisigWatchdog, MultisigWatchdogConfig},
    service, state::AppState,
};
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
    // Round 21: probe the starid `/describe` endpoint before mounting the
    // DidWebvhResolver into the resolver chain. A misconfigured URL would
    // otherwise silently break `did:webvh` lookups; here we strip the
    // resolver from the chain on probe failure and log a warning.
    if let Some(url) = config.starid_webvh_resolver_url.clone() {
        match soland::state::did_resolver_chain::probe_starid_describe(
            &url,
            std::time::Duration::from_secs(3),
        )
        .await
        {
            Ok(()) => {
                tracing::info!(
                    starid_url = %url,
                    "starid /describe probe succeeded — DidWebvhResolver enabled"
                );
            }
            Err(error) => {
                tracing::warn!(
                    starid_url = %url,
                    %error,
                    "starid /describe probe failed — DidWebvhResolver omitted from chain"
                );
                config.starid_webvh_resolver_url = None;
            }
        }
    }
    let state = AppState::new(config.clone(), Db::from_env()?);

    // MAL-11 round 25 — spawn the multisig leader-election watchdog. The
    // task wakes every 30s by default, scans `multisig_pending` for rows
    // whose threshold is met + canonical_b64 is non-empty, claims an
    // unleased row, and aggregates via SDK `ThresholdAggregator`. Returns
    // a JoinHandle we drop on the floor — the task lives for the process
    // lifetime and shutdown_signal teardown closes the runtime.
    let watchdog_config = MultisigWatchdogConfig::for_service(&state.config.service_did);
    let _watchdog = MultisigWatchdog::new(state.clone(), watchdog_config).spawn();

    let acceptor = TcpListener::new(config.bind.to_string()).bind().await;
    tracing::info!(
        bind = %config.bind,
        public_base_url = %config.public_base_url,
        service_did = %config.service_did,
        blob_root = %config.blob_root.display(),
        development_mode = config.development_mode,
        storage = state.db.mode(),
        "starting soland"
    );

    let server = Server::new(acceptor);
    let handle = server.handle();
    tokio::spawn(async move {
        shutdown_signal().await;
        // `None` means wait until all in-flight requests finish before
        // closing the listener.
        handle.stop_graceful(None);
    });
    server.serve(service(state)).await;
    tracing::info!("soland stopped");
    Ok(())
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
