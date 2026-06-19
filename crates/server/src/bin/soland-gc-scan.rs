//! `cargo run --bin soland-gc-scan -- --realm-id <id> [--dry-run]`
//!
//! Walks the durable Move + Seal stores and emits the list of
//! GC-eligible Moves as JSON on stdout. The `--dry-run` flag is the
//! only mode currently supported (deletion is a follow-up).

use soland::config::AppConfig;
use soland::db::Db;
use soland::gc;
use soland::state::AppState;

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
    let state = AppState::new(config, db);
    state.hydrate().await?;

    let candidates = match realm_id.as_deref() {
        Some(id) => {
            let realm = cokret_sdk::RealmId::new(id.to_owned())
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
