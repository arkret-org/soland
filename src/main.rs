use salvo::prelude::*;
use soland::{artifacts, config::AppConfig, db::Db, service, state::AppState};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // Fail fast at startup if a bundled Contrix artifact is malformed instead
    // of crashing the first request that touches the offending OnceLock.
    artifacts::validate_embedded_artifacts()?;

    let config = AppConfig::from_env_and_args()?;
    if let Some(database_url) = &config.database_url {
        unsafe {
            std::env::set_var("DATABASE_URL", database_url);
        }
    }
    let state = AppState::new(config.clone(), Db::from_env()?);
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
    Server::new(acceptor).serve(service(state)).await;
    Ok(())
}
