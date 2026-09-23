//! `http_api` integration-test binary.
//!
//! The 9868-line monolithic test file was split into per-domain submodules
//! living alongside this entry point in `tests/http_api/`. Cargo auto-discovers
//! `tests/<name>/main.rs` as the integration-test binary `<name>`, so the
//! sibling submodules resolve through plain `mod` declarations (the directory
//! layout matches Rust's default module resolution — no `#[path]` needed).

#[path = "current_common.rs"]
mod common;

mod admin_b_track;
mod admin_production_queries;
mod blob_resumable;
mod deactivation_push_fanout;
mod health;
mod history_authority;
mod openapi;
mod organization_registration;
mod retired_seal_mls_routes;
mod retired_seal_pending_control;
mod seal_frontier;
mod self_signer_keys_query;
