//! `cargo run --bin soland-gc-scan -- --realm-id <id> [--dry-run]`
//!
//! Walks the durable Move + Seal stores and emits the list of
//! GC-eligible Moves as JSON on stdout. The `--dry-run` flag is the
//! only mode currently supported (deletion is a follow-up).

use soland::process_config::arg_value;
use soland_http::config::{AppConfig, StartupOverrides};
use soland_http::gc;
use soland_storage_postgres::Db;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let realm_id = arg_value(&args, "--realm-id");
    let dry_run = args.iter().any(|a| a == "--dry-run");

    if !dry_run {
        eprintln!("soland-gc-scan: only --dry-run is supported (deletion is a follow-up)");
        std::process::exit(2);
    }
    let values = soland::process_config::load(&args)?;
    let config = AppConfig::from_values(&values, StartupOverrides::default())?;
    let db = Db::connect(
        config.database_url.as_deref(),
        soland_storage_postgres::PoolTuning {
            max_size: config.db_pool_max_size,
            acquire_timeout_seconds: config.db_pool_acquire_timeout_seconds,
        },
    )
    .await?;
    let bootstrap = soland::bootstrap::resolve_and_build_persistence(&config, &db).await?;
    let resolution_commitment = bootstrap
        .resolution_commitment
        .clone()
        .ok_or_else(|| anyhow::anyhow!("serving service identity has no resolution commitment"))?;
    let state = soland::runtime::build_app_state(
        config,
        db,
        bootstrap.persistence,
        bootstrap.state,
        resolution_commitment,
        bootstrap.signing_seed,
    )?;
    state.hydrate().await?;

    let candidates = match realm_id.as_deref() {
        Some(id) => {
            let realm = arkret_identifiers::RealmId::new(id.to_owned())
                .map_err(|e| anyhow::anyhow!("invalid --realm-id: {e}"))?;
            gc::scan_gc_candidates(&state, &realm).await
        }
        None => gc::scan_all_realms(&state).await,
    };

    let report = serde_json::json!({
        "realm_id": realm_id,
        "dry_run": true,
        "total": candidates.len(),
        "candidates": candidates,
    });
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
