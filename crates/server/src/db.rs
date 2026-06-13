//! Database entrypoint for `soland`.
//!
//! Kept as a small re-export wrapper so existing `crate::db::{Db, PgPool}` call
//! sites stay stable while the actual bootstrap/ migration logic lives in
//! `soland-data`.
pub use soland_data::{Db, PgPool};
