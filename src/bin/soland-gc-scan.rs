//! `cargo run --bin soland-gc-scan -- --space-id <id> [--dry-run]`
//!
//! MAL-13 (round 25) — walk the durable Move + Anchor stores and emit the
//! list of GC-eligible Moves as JSON on stdout. The `--dry-run` flag is
//! the only mode currently supported (deletion is a follow-up).

use soland::config::AppConfig;
use soland::db::Db;
use soland::gc;
use soland::state::AppState;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let space_id = arg_value(&args, "--space-id");
    let dry_run = args.iter().any(|a| a == "--dry-run");

    if !dry_run {
        eprintln!(
            "soland-gc-scan: only --dry-run is supported in round 25 (deletion is a follow-up)"
        );
        std::process::exit(2);
    }

    dotenvy::dotenv().ok();
    let config = AppConfig::from_env_and_args()?;
    let db = Db::from_env()?;
    let state = AppState::new(config, db);

    let candidates = match space_id.as_deref() {
        Some(id) => {
            let space = contrix_sdk::SpaceId::new(id.to_owned())
                .map_err(|e| anyhow::anyhow!("invalid --space-id: {e}"))?;
            gc::scan_gc_candidates(&state, &space)
        }
        None => gc::scan_all_spaces(&state),
    };

    let report = serde_json::json!({
        "space_id": space_id,
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
