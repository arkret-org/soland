//! Durable SecurityRotation coordinator worker.
//!
//! `revoke` is a coordinator-owned step (security-transactions.md §3): the
//! Station advances it, never a client `continue`. Every transition is a
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
            crate::routing::identity::recovery::sweep_rotation_revokes(&state).await;
        }
    }))
}
