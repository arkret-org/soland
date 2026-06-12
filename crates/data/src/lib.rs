//! Soland data persistence crate.
//!
//! This crate owns durable storage concerns:
//!
//! - database bootstrap, connection pools, readiness-visible migration state
//! - embedded Diesel migrations
//! - Diesel table schema generated from those migrations
//! - reusable raw SQL result rows that have no server-domain behavior
//!
//! The next layer that belongs here is the persisted model/store layer:
//! `*Record` row types, `*Store` repository traits, `Pg*Store` implementations,
//! and the in-memory test stores that implement the same traits. Those pieces
//! currently remain in `soland-server` because their types are still mixed into
//! `AppState`; move the model types first, then the store traits and backends.
//!
//! Request routing, reducers, authorization, realtime notifications, background
//! workers, object storage policy, and `AppState` orchestration stay in
//! `soland-server`.
pub mod db;
pub mod query_rows;
pub mod schema;

pub use db::{Db, PgPool};
