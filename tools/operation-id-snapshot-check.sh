#!/usr/bin/env bash
# operation-id-snapshot-check.sh — CI gate
#
# Compares the operation_id values that soland's source code registers
# (any `operation_id = "ck.*"` string literal under `src/`) against the
# canonical spec registry at
# `cokret-spec/spec/v1/artifacts/registry/operation-registry.json`.
#
# Exit codes:
#   0 — every soland-registered operation_id is in the canonical
#       registry, or is namespaced as `ck.extension.soland.*`, or is
#       listed in `scripts/operation_id_baseline.json` as a
#       grandfathered allow-listed id.
#   1 — at least one soland-registered operation_id is none of the
#       above — wire-breaking drift between soland and the spec.
#   2 — environment / file-shape problem (missing registry, missing
#       baseline file, no jq, ...). Distinguishable from a real drift
#       so CI can mark the job "errored" instead of "failed".
#
# This shell script intentionally mirrors the in-tree Rust gate
# (`tests/conformance_gates.rs::operation_ids_are_registered_or_namespaced`).
# That test is the source of truth on a developer machine because it
# runs as part of `cargo test`; this script gives CI a cheap, no-Rust
# gate that can run before `cargo test` finishes, and also gives
# operators a quick `bash` reproduction.
#
# Usage:
#   ./tools/operation-id-snapshot-check.sh                     # default paths
#   ./tools/operation-id-snapshot-check.sh /path/to/spec       # override spec root
#
# Hook into the workspace `just` recipe via `just conformance-gates`,
# which calls this script in addition to the cargo test gate.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOLAND_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

SPEC_ROOT_DEFAULT="${SOLAND_ROOT}/../cokret-spec"
SPEC_ROOT="${1:-${SPEC_ROOT_DEFAULT}}"
REGISTRY="${SPEC_ROOT}/spec/v1/artifacts/registry/operation-registry.json"
BASELINE="${SOLAND_ROOT}/scripts/operation_id_baseline.json"
SRC_ROOT="${SOLAND_ROOT}/src"

if ! command -v jq >/dev/null 2>&1; then
  echo "ERROR: jq is required (https://jqlang.github.io/jq/)." >&2
  exit 2
fi
if [[ ! -f "${REGISTRY}" ]]; then
  echo "ERROR: spec registry not found at ${REGISTRY}" >&2
  echo "       Pass the spec checkout root as the first argument." >&2
  exit 2
fi
if [[ ! -f "${BASELINE}" ]]; then
  echo "ERROR: grandfathered baseline not found at ${BASELINE}" >&2
  exit 2
fi
if [[ ! -d "${SRC_ROOT}" ]]; then
  echo "ERROR: src/ not found at ${SRC_ROOT}" >&2
  exit 2
fi

# Canonical set — recurse into surface_groups[*].operations[] AND
# operations[*].operation_id so the script keeps working when the
# registry shape evolves.
mapfile -t CANONICAL < <(jq -r '
  [ .. | objects | .operation_id? // empty,
    .. | objects | .operations? // empty | .[]? | strings
  ] | unique | .[]
' "${REGISTRY}")

if [[ ${#CANONICAL[@]} -eq 0 ]]; then
  echo "ERROR: operation-registry.json yielded zero operation_id values." >&2
  echo "       Registry shape may have changed; update this gate." >&2
  exit 2
fi

mapfile -t GRANDFATHERED < <(jq -r '
  .grandfathered_operation_ids // [] | .[]
' "${BASELINE}")

# Scan soland's src/ for `operation_id = "ck.*"` literals.
# - exclude comments (the SDK's own Rust comments document spec ids)
# - tolerate both `=` and `: "ck.foo"` shapes
mapfile -t SOLAND_OPS < <(
  grep -RhoE 'operation_id[[:space:]]*=[[:space:]]*"ck\.[A-Za-z0-9_.]+"' "${SRC_ROOT}" \
    | sed -E 's/.*"(ck\.[A-Za-z0-9_.]+)".*/\1/' \
    | sort -u
)

failures=()
for op in "${SOLAND_OPS[@]}"; do
  if [[ "${op}" == ck.extension.soland.* ]]; then
    continue
  fi
  is_canonical=0
  for c in "${CANONICAL[@]}"; do
    if [[ "${op}" == "${c}" ]]; then
      is_canonical=1
      break
    fi
  done
  if [[ ${is_canonical} -eq 1 ]]; then
    continue
  fi
  is_grandfathered=0
  for g in "${GRANDFATHERED[@]}"; do
    if [[ "${op}" == "${g}" ]]; then
      is_grandfathered=1
      break
    fi
  done
  if [[ ${is_grandfathered} -eq 1 ]]; then
    continue
  fi
  failures+=("${op}")
done

if [[ ${#failures[@]} -ne 0 ]]; then
  echo "operation-id snapshot drift — the following soland-registered operation_ids" >&2
  echo "are not in the canonical registry, not in scripts/operation_id_baseline.json," >&2
  echo "and not namespaced as ck.extension.soland.*:" >&2
  for op in "${failures[@]}"; do
    echo "  - ${op}" >&2
  done
  echo "" >&2
  echo "Resolution:" >&2
  echo "  1. If the operation_id should be canonical, add it to the spec registry." >&2
  echo "  2. If it is a soland-private extension, rename it to ck.extension.soland.*." >&2
  echo "  3. If it is a known grandfathered id, add it to scripts/operation_id_baseline.json." >&2
  exit 1
fi

echo "operation-id snapshot OK (${#SOLAND_OPS[@]} ids scanned, registry has ${#CANONICAL[@]} canonical ids)"
