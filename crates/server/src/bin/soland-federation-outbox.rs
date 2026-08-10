//! Operator CLI for the durable federation outbox.
//!
//! ```text
//! soland-federation-outbox list [--state pending|leased|delivered|policy_suppressed|dead_lettered|superseded] [--limit N]
//! soland-federation-outbox list --dead-letters [--limit N]
//! soland-federation-outbox inspect <outbox-id|dead-letter-id>
//! soland-federation-outbox requeue <dead-letter-id> --operator <did> --reason <text>
//! ```
//!
//! `requeue` never resurrects the terminal row: it re-validates the peer, the
//! egress policy and the stored request, then mints a fresh intent under a new
//! `Idempotency-Key` and stamps the operator audit onto the dead letter — all
//! in one transaction. See `routing::federation::outbox_operator`.

use soland_http::config::AppConfig;
use soland_http::routing::federation::outbox_operator::{self, DEFAULT_LIST_LIMIT};
use soland_services::federation::FederationDeliveryState;
use soland_storage_postgres::Db;

const USAGE: &str = "usage:\n  \
    soland-federation-outbox list [--state <state>] [--limit N]\n  \
    soland-federation-outbox list --dead-letters [--limit N]\n  \
    soland-federation-outbox inspect <outbox-id|dead-letter-id>\n  \
    soland-federation-outbox requeue <dead-letter-id> --operator <did> --reason <text>";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(command) = args.first().cloned() else {
        eprintln!("{USAGE}");
        std::process::exit(2);
    };

    dotenvy::dotenv().ok();
    let config = AppConfig::from_env_and_args()?;
    let db = Db::from_env().await?;
    if db.pool.is_none() {
        eprintln!(
            "soland-federation-outbox: DATABASE_URL is not configured; the in-memory outbox is \
             per-process and has nothing for an operator to inspect"
        );
        std::process::exit(2);
    }
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

    let limit = arg_value(&args, "--limit")
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_LIST_LIMIT);

    let report = match command.as_str() {
        "list" if args.iter().any(|arg| arg == "--dead-letters") => {
            let rows = outbox_operator::list_dead_letters(&state, limit)
                .await
                .map_err(anyhow::Error::msg)?;
            serde_json::json!({ "dead_letters": rows })
        }
        "list" => {
            let lifecycle = match arg_value(&args, "--state") {
                Some(value) => parse_state(&value)?,
                None => FederationDeliveryState::Pending,
            };
            let rows = outbox_operator::list_by_state(&state, lifecycle, limit)
                .await
                .map_err(anyhow::Error::msg)?;
            serde_json::json!({ "state": lifecycle.as_str(), "rows": rows })
        }
        "inspect" => {
            let id = positional(&args).ok_or_else(|| anyhow::anyhow!("{USAGE}"))?;
            let detail = outbox_operator::inspect(&state, &id)
                .await
                .map_err(anyhow::Error::msg)?;
            serde_json::to_value(detail)?
        }
        "requeue" => {
            let id = positional(&args).ok_or_else(|| anyhow::anyhow!("{USAGE}"))?;
            let operator = arg_value(&args, "--operator")
                .ok_or_else(|| anyhow::anyhow!("requeue requires --operator <did>"))?;
            let reason = arg_value(&args, "--reason")
                .ok_or_else(|| anyhow::anyhow!("requeue requires --reason <text>"))?;
            let outcome = outbox_operator::requeue_dead_letter(&state, &id, &operator, &reason)
                .await
                .map_err(anyhow::Error::msg)?;
            serde_json::to_value(outcome)?
        }
        other => {
            eprintln!("soland-federation-outbox: unknown command {other}\n{USAGE}");
            std::process::exit(2);
        }
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn parse_state(value: &str) -> anyhow::Result<FederationDeliveryState> {
    FederationDeliveryState::parse(value.trim()).ok_or_else(|| {
        anyhow::anyhow!(
            "unknown --state {value}; expected pending, leased, delivered, policy_suppressed, \
             dead_lettered or superseded"
        )
    })
}

/// The first argument after the subcommand that is not a flag or a flag value.
fn positional(args: &[String]) -> Option<String> {
    let mut iter = args.iter().skip(1);
    while let Some(arg) = iter.next() {
        if arg.starts_with("--") {
            if !arg.contains('=') {
                iter.next();
            }
            continue;
        }
        return Some(arg.clone());
    }
    None
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
