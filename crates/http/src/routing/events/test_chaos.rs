//! Debug-only timing controls for real atomic-commit race tests.
//!
//! These controls never decide an outcome and never replace durable storage.
//! They only pause a matching request at a named boundary so Cotest can order
//! two real requests against the shared PostgreSQL create-once boundary.

use std::path::Path;
use std::time::{Duration, Instant};

use serde::Deserialize;

use crate::state::AppState;

pub(crate) const PRE_IDENTITY_ANCHOR_COMMIT: &str = "pre_identity_anchor_commit";

const ENABLE_ENV: &str = "SOLAND_ENABLE_TEST_ENDPOINTS";
const CONTROL_FILE_ENV: &str = "SOLAND_TEST_CHAOS_CONTROL_FILE";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChaosControl {
    breakpoint: String,
    transaction_id: String,
    delay_ms: u64,
    reached_file: String,
    #[serde(default)]
    release_file: Option<String>,
}

fn explicitly_enabled() -> bool {
    cfg!(debug_assertions)
        && std::env::var(ENABLE_ENV).is_ok_and(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes"
            )
        })
}

/// Pause a matching request without changing the durable decision semantics.
pub(crate) async fn pause_at(state: &AppState, breakpoint: &'static str, transaction_id: &str) {
    if !state.config().development_mode || !explicitly_enabled() {
        return;
    }
    let Ok(control_path) = std::env::var(CONTROL_FILE_ENV) else {
        return;
    };
    let Ok(bytes) = std::fs::read(&control_path) else {
        return;
    };
    let Ok(control) = serde_json::from_slice::<ChaosControl>(&bytes) else {
        tracing::warn!(%control_path, "ignoring malformed Soland test-chaos control file");
        return;
    };
    if control.breakpoint != breakpoint
        || control.transaction_id != transaction_id
        || control.delay_ms == 0
    {
        return;
    }

    if let Err(error) = std::fs::write(&control.reached_file, breakpoint.as_bytes()) {
        tracing::warn!(
            %error,
            reached_file = %control.reached_file,
            "failed to publish Soland test-chaos reached marker"
        );
        return;
    }

    tracing::warn!(
        breakpoint,
        transaction_id,
        delay_ms = control.delay_ms,
        "pausing at Soland test-only atomic commit boundary"
    );
    let deadline = Instant::now() + Duration::from_millis(control.delay_ms);
    loop {
        if control
            .release_file
            .as_deref()
            .is_some_and(|path| Path::new(path).exists())
            || Instant::now() >= deadline
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
