//! End-to-end HTTP integration tests for `POST /_soland/peer/moves` and
//! `POST /_soland/peer/seals`, plus the notary signing pipeline, the
//! events.subscribe streaming surface, HLC replay protection, the
//! production Ed25519 verifier, and the admin cells read surface.
//!
//! The 1738-line monolithic test file was split into per-topic submodules
//! living alongside this entry point in `tests/move_seal_wire/`. Cargo
//! auto-discovers `tests/<name>.rs` as the integration-test binary
//! `<name>`. Because this file is itself the test-binary crate root, child
//! `mod` declarations resolve against `tests/`, so each one carries an
//! explicit `#[path]` into the sibling `move_seal_wire/` directory. Shared
//! helpers live in `move_seal_wire/common.rs`; submodules pull them in via
//! `use super::common::*;`.

#[path = "move_seal_wire/common.rs"]
mod common;

#[path = "move_seal_wire/admin_cells.rs"]
mod admin_cells;
#[path = "move_seal_wire/events_subscribe.rs"]
mod events_subscribe;
#[path = "move_seal_wire/hlc_replay.rs"]
mod hlc_replay;
#[path = "move_seal_wire/move_seal.rs"]
mod move_seal;
#[path = "move_seal_wire/notary.rs"]
mod notary;
#[path = "move_seal_wire/verifier_signatures.rs"]
mod verifier_signatures;
