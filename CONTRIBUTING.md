# Contributing to soland

Thanks for considering a contribution! soland is a reference Cokret v1
principal server; the protocol contract lives in
[`cokret-spec`](https://github.com/cokret/cokret-spec) and the Rust SDK
in [`cokret-rust-sdk`](https://github.com/cokret/cokret-rust-sdk).

## Pre-commit hook setup

After cloning, enable the project's pre-commit hooks:

```sh
git config core.hooksPath .githooks
```

The hook runs `cargo fmt --all -- --check` plus `cargo clippy --no-deps -- -D
warnings` on staged Rust changes. If `.githooks/` is missing or you want a
richer hook, copy `.githooks/pre-commit` from
[`cokret-rust-sdk`](https://github.com/cokret-dev/cokret-rust-sdk) and
adapt to your local toolchain.

## Repository layout

soland depends on the `cokret` SDK at a sibling path. The CI workflows clone
both repositories side by side; reproduce the same layout locally:

```
cokret-dev/
├── cokret-rust-sdk/
│   └── crates/sdk
└── soland/                # this repo
    ├── src/
    ├── tests/
    └── Cargo.toml
```

The Cargo `path = "../cokret-rust-sdk/crates/sdk"` reference assumes this
layout. If you check out into a different structure, override the dependency
locally with a `[patch.crates-io]` entry in `~/.cargo/config.toml` rather than
editing `Cargo.toml`.

## Toolchain

- Rust **stable** (MSRV: see `rust-version` in `Cargo.toml`).
- `cargo fmt`, `cargo clippy`, `cargo deny` all run in CI; install them with
  `rustup component add rustfmt clippy` and `cargo install cargo-deny`.
- PostgreSQL is required to exercise the persistence layer end to end, but
  unit tests and the in-memory integration suite run without a DB.

## Workflow

1. Fork and create a topic branch (`fix/short-description` or
   `feat/short-description`).
2. Run the local checks before pushing:

   ```bash
   cargo fmt --all -- --check
   cargo clippy --all-targets --locked -- -D warnings
   cargo test --locked
   ```

3. Open a PR; CI runs `Rust`, `Docker`, `Typos`, and `Supply chain` (cargo-deny)
   workflows. All must be green before review.
4. Reference the corresponding `_todos.md` ID in the PR description (e.g. `F2`,
   `Sec-1`). New audit findings should be added to `_todos.md` in the same PR.

## Coding conventions

- Match the `rustfmt.toml` style — `cargo fmt` enforces it.
- Avoid `unsafe` outside `src/main.rs` (the env propagation is the only
  approved exception today; see the comment).
- Prefer typed errors via `crate::error::ErrorCode` over hand-typed strings;
  this is the F3 migration path.
- Keep handlers as `#[endpoint]` (Salvo OpenAPI variant). When you add a new
  route, mount it in [`src/lib.rs`](src/lib.rs) and ensure
  `cokret_openapi_spec_contains_facet_projection_contracts` still passes.
- Don't introduce new `serde_json::Value` blobs at the wire boundary if a
  typed `wire::*` shape would do — the OpenAPI doc improves alongside this.

## Tests

- Unit tests live next to the code (`src/<module>.rs::tests`).
- HTTP integration tests live in `tests/http_api.rs`; the file is large and
  scheduled for split (`_todos.md` Q7).
- The OpenAPI doc test (`cokret_openapi_spec_contains_facet_projection_contracts`)
  is load-bearing — adding or removing routes that the test enumerates needs
  a corresponding update.

## Reporting bugs

Use a regular GitHub issue for non-security bugs. For vulnerabilities, see
[SECURITY.md](SECURITY.md).

## License

All contributions are licensed under Apache-2.0 (see [LICENSE](LICENSE)).
By submitting a PR you agree your contribution is licensed under the same
terms.
