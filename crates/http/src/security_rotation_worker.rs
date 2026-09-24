//! Durable SecurityRotation coordinator worker.
//!
//! `revoke`, `upload_new_material`, `switch_authoritative_pointer` and
//! `erase_old_material` are coordinator-owned steps (security-transactions.md
//! §1.1, §3): the Station advances them, never a client request. Every transition is a
//! registered storage unit, so a sweep that finds a transaction mid-way only
//! resumes it; the process holds no rotation state of its own.

use std::sync::Arc;

use crate::state::AppState;

const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

pub fn spawn(state: AppState) -> Arc<tokio::task::JoinHandle<()>> {
    Arc::new(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(POLL_INTERVAL);
        loop {
            ticker.tick().await;
            crate::routing::identity::recovery::sweep_rotation_worker(&state).await;
        }
    }))
}
