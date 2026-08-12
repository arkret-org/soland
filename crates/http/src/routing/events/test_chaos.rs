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
pub(crate) const PRE_DIRECT_REPAIR_DEVICE_BATCH_COMMIT: &str =
    "pre_direct_repair_device_batch_commit";
pub(crate) const POST_DIRECT_REPAIR_COMMIT_PRE_RESPONSE: &str =
    "post_direct_repair_commit_pre_response";

const ENABLE_ENV: &str = "SOLAND_ENABLE_TEST_ENDPOINTS";
const CONTROL_FILE_ENV: &str = "SOLAND_TEST_CHAOS_CONTROL_FILE";
const BREAKPOINT_ENV: &str = "SOLAND_TEST_CHAOS_BREAKPOINT";
const DELAY_MS_ENV: &str = "SOLAND_TEST_CHAOS_DELAY_MS";
const OPERATION_ID_ENV: &str = "SOLAND_TEST_CHAOS_OPERATION_ID";

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

/// Longest pause any chaos control may request.
///
/// The delay is operator-supplied and sits on a request path, so it is bounded
/// rather than trusted: a mistyped value should slow one test down, not hang a
/// connection until the client times out.
const MAX_DELAY: Duration = Duration::from_secs(30);

/// Whether the test-only timing controls may run at all.
///
/// The single gate for every chaos hook. Three independent conditions must all
/// hold: a debug build, an explicit opt-in variable, and `development_mode`.
/// `maybe_delay_before_event_response` used to check only the third of these,
/// so a release binary running with `SOLAND_DEVELOPMENT_MODE=true` would honour
/// an arbitrary `SOLAND_TEST_CHAOS_DELAY_MS` on the Event submission response
/// path. Two hooks of the same class must not have two different gates.
pub(crate) fn enabled(state: &AppState) -> bool {
    cfg!(debug_assertions)
        && state.config().development_mode
        && std::env::var(ENABLE_ENV).is_ok_and(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes"
            )
        })
}

/// Pause a matching request without changing the durable decision semantics.
pub(crate) async fn pause_at(state: &AppState, breakpoint: &'static str, transaction_id: &str) {
    if !enabled(state) {
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
    let deadline = Instant::now() + Duration::from_millis(control.delay_ms).min(MAX_DELAY);
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

/// Pause just before an accepted Event's response is written.
///
/// Cotest uses this to order a second real request against the first one's
/// commit. Like [`pause_at`] it only delays: the durable decision has already
/// been made and is not consulted here.
pub(crate) async fn maybe_delay_before_event_response(
    state: &AppState,
    operation_id: Option<&str>,
    event_id: &str,
) {
    if !enabled(state) {
        return;
    }
    let Ok(breakpoint) = std::env::var(BREAKPOINT_ENV) else {
        return;
    };
    if !matches!(
        breakpoint.as_str(),
        "post_commit_pre_response" | "post_wal_pre_response"
    ) {
        return;
    }
    let Some(delay) = std::env::var(DELAY_MS_ENV)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .map(|value| Duration::from_millis(value).min(MAX_DELAY))
    else {
        return;
    };
    if let Ok(expected) = std::env::var(OPERATION_ID_ENV)
        && Some(expected.as_str()) != operation_id
        && expected != event_id
    {
        return;
    }
    tracing::warn!(
        breakpoint = %breakpoint,
        delay_ms = delay.as_millis(),
        event_id,
        operation_id,
        "pausing at Soland test-only post-commit boundary"
    );
    tokio::time::sleep(delay).await;
}
