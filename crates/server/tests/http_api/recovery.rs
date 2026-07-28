//! Integration tests — recovery policy, session, and DID-recovery backup verification.
//!
//! This module is a structural root: shared helpers and constants live in
//! [`helpers`], and each test cluster sits in its own submodule. Test
//! submodules reach the shared recovery fixtures via `use super::helpers::*;`
//! and the cross-domain test fixtures via `use crate::common::*;`.

mod helpers;

mod did_recovery_backup;
mod policy;
mod session;
