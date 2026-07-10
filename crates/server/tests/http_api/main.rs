//! `http_api` integration-test binary.
//!
//! The 9868-line monolithic test file was split into per-domain submodules
//! living alongside this entry point in `tests/http_api/`. Cargo auto-discovers
//! `tests/<name>/main.rs` as the integration-test binary `<name>`, so the
//! sibling submodules resolve through plain `mod` declarations (the directory
//! layout matches Rust's default module resolution — no `#[path]` needed).

mod common;

mod account_data;
mod account_workflow;
mod admin_b_track;
mod admin_production_queries;
mod agent_bridge;
mod agents;
mod auth;
mod blob_resumable;
mod cors_config;
mod devices_webrtc;
mod direct_conversations;
mod directory_index;
mod events;
mod federation;
mod health;
mod identity;
mod lifecycle;
mod mimi;
mod openapi;
mod policy_snapshot;
mod projection;
mod push_keys;
mod read_receipts;
mod recovery;
