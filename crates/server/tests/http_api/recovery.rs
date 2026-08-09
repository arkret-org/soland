//! Integration tests — recovery policy and session verification.
//!
//! This module is a structural root: shared helpers and constants live in
//! [`helpers`], and each test cluster sits in its own submodule. Test
//! submodules reach the shared recovery fixtures via `use super::helpers::*;`
//! and the cross-domain test fixtures via `use crate::common::*;`.

mod helpers;

mod policy;
mod session;
