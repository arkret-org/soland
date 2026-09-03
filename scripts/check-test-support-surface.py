#!/usr/bin/env python3
"""Reject known test-only accessors that leak into production builds."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
TEST_CFG = '#[cfg(any(test, feature = "test-support"))]'
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

    if failures:
        print("test-support surface gate failed:", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1
    print("test-support surface gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
