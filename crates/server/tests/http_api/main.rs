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
mod agent_pairing_ceremony;
mod agents;
mod auth;
mod blob_resumable;
mod backup_listing;
mod calendar_rsvp;
mod cors_config;
mod deactivation_push_fanout;
mod devices_webrtc;
mod direct_conversations;
mod directory_index;
mod events;
mod federation;
mod health;
mod identity;
mod invites;
mod lifecycle;
mod mimi;
mod openapi;
mod organization_registration;
mod projection;
mod push_keys;
mod read_receipts;
mod recovery;
mod seal_frontier;
mod stage_axis;
