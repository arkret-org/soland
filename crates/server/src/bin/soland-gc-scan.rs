//! `cargo run --bin soland-gc-scan -- --realm-id <id> [--dry-run]`
//!
//! Walks the durable Move + Seal stores and emits the list of
//! GC-eligible Moves as JSON on stdout. The `--dry-run` flag is the
//! only mode currently supported (deletion is a follow-up).

use soland_http::config::AppConfig;
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

    dotenvy::dotenv().ok();
    let config = AppConfig::from_env_and_args()?;
    let db = Db::from_env().await?;
    let bootstrap = soland::bootstrap::resolve_and_build_persistence(&config, &db).await?;
    let state = soland::runtime::build_app_state(
        config,
        db,
        bootstrap.persistence,
        bootstrap.state,
        bootstrap.signing_seed,
    )?;
    state.hydrate().await?;

    let candidates = match realm_id.as_deref() {
        Some(id) => {
            let realm = arkret_core::RealmId::new(id.to_owned())
                .map_err(|e| anyhow::anyhow!("invalid --realm-id: {e}"))?;
            gc::scan_gc_candidates(&state, &realm)
        }
        None => gc::scan_all_realms(&state),
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

fn arg_value(args: &[String], name: &str) -> Option<String> {
    let mut iter = args.iter();
    while let Some(a) = iter.next() {
        if a == name {
            return iter.next().cloned();
        }
        if let Some(value) = a.strip_prefix(&format!("{name}=")) {
            return Some(value.to_owned());
        }
    }
    None
}
