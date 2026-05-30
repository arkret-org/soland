//! `http_api` integration-test binary.
//!
//! The 9868-line monolithic test file was split into per-domain
//! submodules under `tests/http_api/`. Cargo treats `tests/*.rs` as
//! integration-test binary entry points, but only compiles top-level
//! `.rs` files as binaries — files in subdirectories are not picked
//! up automatically. We re-bind each submodule with `#[path]` so the
//! source lives organized under `tests/http_api/` while still being
//! part of this one integration-test binary.

#[path = "http_api/common.rs"]
mod common;

#[path = "http_api/account_data.rs"]
mod account_data;
#[path = "http_api/account_workflow.rs"]
mod account_workflow;
#[path = "http_api/agent_bridge.rs"]
mod agent_bridge;
#[path = "http_api/auth.rs"]
mod auth;
#[path = "http_api/cors_config.rs"]
mod cors_config;
#[path = "http_api/devices_webrtc.rs"]
mod devices_webrtc;
#[path = "http_api/directory_index.rs"]
mod directory_index;
#[path = "http_api/events.rs"]
mod events;
#[path = "http_api/federation.rs"]
mod federation;
#[path = "http_api/health.rs"]
mod health;
#[path = "http_api/identity.rs"]
mod identity;
#[path = "http_api/lifecycle.rs"]
mod lifecycle;
#[path = "http_api/mimi.rs"]
mod mimi;
#[path = "http_api/policy_snapshot.rs"]
mod policy_snapshot;
#[path = "http_api/projection.rs"]
mod projection;
#[path = "http_api/push_keys.rs"]
mod push_keys;
#[path = "http_api/recovery.rs"]
mod recovery;
