#!/usr/bin/env python3
"""Reject known test-only accessors and modules that leak into production builds.

Two shapes:

* `SURFACES` — a `pub fn` that only tests should reach, which must carry
  `#[cfg(any(test, feature = "test-support"))]`.
* `GATED_MODULES` — a whole module that must not be compiled into a default
  build. The development conformance harness is the case this exists for:
  `soland_services::conformance_basis` builds Seals with a notary signer
  derived from a caller-supplied 32-byte seed, and
  `soland_http::routing::conformance` is the HTTP surface that drives it.
  `development_mode` decides whether the namespace is *mounted*; these
  attributes decide whether it is *compiled*, which is what keeps the seed
  constructor out of the release binary.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
TEST_CFG = '#[cfg(any(test, feature = "test-support"))]'
# `(relative_path, module_declaration): required_attribute`
GATED_MODULES = {
    (
        "crates/services/src/lib.rs",
        "pub mod conformance_basis;",
    ): '#[cfg(any(test, feature = "test-support"))]',
    (
        "crates/http/src/routing/mod.rs",
        "pub(crate) mod conformance;",
    ): '#[cfg(any(test, feature = "conformance-harness"))]',
}

SURFACES = {
    "crates/http/src/config.rs": ("test_default",),
    "crates/services/src/events.rs": ("test_index",),
    "crates/services/src/persistence.rs": ("shared_for_tests",),
    "crates/services/src/projection.rs": ("test_state",),
    "crates/storage/src/records.rs": ("with_coalescing_lane",),
}


def main() -> int:
    failures: list[str] = []
    for relative_path, names in SURFACES.items():
        source = (ROOT / relative_path).read_text(encoding="utf-8")
        for name in names:
            definitions = list(
                re.finditer(
                    rf"(?m)^\s*pub(?:\([^)]*\))?\s+(?:async\s+)?fn\s+{re.escape(name)}\b",
                    source,
                )
            )
            for definition in definitions:
                prefix = source[max(0, definition.start() - 320) : definition.start()]
                attribute_block = prefix[prefix.rfind("\n\n") + 2 :]
                if TEST_CFG not in attribute_block:
                    line = source.count("\n", 0, definition.start()) + 1
                    failures.append(f"{relative_path}:{line}: {name} lacks {TEST_CFG}")

    for (relative_path, declaration), attribute in GATED_MODULES.items():
        source = (ROOT / relative_path).read_text(encoding="utf-8")
        if declaration not in source:
            failures.append(
                f"{relative_path}: `{declaration}` is gone — update this gate "
                f"or restore the declaration"
            )
            continue
        if f"{attribute}\n{declaration}" not in source:
            line = source.count("\n", 0, source.index(declaration)) + 1
            failures.append(
                f"{relative_path}:{line}: `{declaration}` is not directly "
                f"preceded by {attribute}"
            )

    if failures:
        print("test-support surface gate failed:", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1
    print(
        f"test-support surface gate passed "
        f"({len(SURFACES)} file(s) of accessors, {len(GATED_MODULES)} gated module(s))"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
