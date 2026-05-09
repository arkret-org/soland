#!/usr/bin/env bash
# Round 28 (2026-05-10) — soland production restore drill.
#
# Inverse of `backup-drill.sh`. Accepts a tarball produced by that script,
# restores the database + keystore, then walks every row in
# `multisig_pending` and asserts each is *still aggregable* (threshold
# arithmetic survives, partials decode, members[] still references the
# row's signers, claim_seq is non-negative, lease invariants hold).
#
# Output:
#   - PASS / FAIL line per row to stdout.
#   - Final summary `RESTORE PASS|FAIL  rows_total=N rows_ok=K rows_bad=M`.
#   - Exit 0 on full PASS, 1 if any row fails the post-restore invariants,
#     2 on prerequisite/IO failure.
#
# Honours PASION_* / SERVERX_* env conventions (same set as backup-drill.sh).

set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "usage: restore-drill.sh <tarball>" >&2
    exit 2
fi
TARBALL="$1"
if [ ! -f "$TARBALL" ]; then
    echo "[restore-drill] FATAL: tarball not found: $TARBALL" >&2
    exit 2
fi

DATABASE_URL="${PASION_DATABASE_URL:-${DATABASE_URL:-}}"
SERVICE_DID="${SERVERX_SERVICE_DID:-did:web:soland.local}"
USE_KEYSTORE="${SERVERX_USE_KEYSTORE:-false}"
WORKDIR="$(mktemp -d -t soland-restore-XXXXXX)"
trap 'rm -rf "$WORKDIR"' EXIT

if [ -z "$DATABASE_URL" ]; then
    echo "[restore-drill] FATAL: DATABASE_URL (or PASION_DATABASE_URL) is unset" >&2
    exit 2
fi

for cmd in pg_restore psql sha256sum tar jq; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "[restore-drill] FATAL: missing prerequisite '$cmd'" >&2
        exit 2
    fi
done

echo "[restore-drill] tarball=$TARBALL service_did=$SERVICE_DID workdir=$WORKDIR"

tar -xzf "$TARBALL" -C "$WORKDIR"

# ── verify manifest checksums ────────────────────────────────────────────
MANIFEST="$WORKDIR/manifest.json"
if [ ! -f "$MANIFEST" ]; then
    echo "[restore-drill] FATAL: tarball missing manifest.json" >&2
    exit 1
fi

declare -A EXPECTED_SHA
while IFS=$'\t' read -r name sha; do
    EXPECTED_SHA[$name]="$sha"
done < <(jq -r '.artifacts | to_entries[] | "\(.key)\t\(.value.sha256)"' "$MANIFEST")

for name in soland-database.dump keystore.json multisig_pending.jsonl; do
    f="$WORKDIR/$name"
    if [ ! -f "$f" ]; then
        echo "[restore-drill] FATAL: tarball missing artifact '$name'" >&2
        exit 1
    fi
    actual="$(sha256sum "$f" | awk '{print $1}')"
    expected="${EXPECTED_SHA[$name]:-}"
    if [ -z "$expected" ] || [ "$actual" != "$expected" ]; then
        echo "[restore-drill] FATAL: checksum mismatch on '$name'" >&2
        echo "  expected=$expected actual=$actual" >&2
        exit 1
    fi
done
echo "[restore-drill] manifest checksums verified"

# ── 1. pg_restore ────────────────────────────────────────────────────────
echo "[restore-drill] step 1/3: pg_restore (clean+if-exists)"
pg_restore --clean --if-exists --no-owner --no-acl \
    --dbname="$DATABASE_URL" "$WORKDIR/soland-database.dump"

# ── 2. keystore restore ──────────────────────────────────────────────────
if [ "$USE_KEYSTORE" = "true" ] && \
   [ "$(jq -r '.skipped // false' "$WORKDIR/keystore.json")" != "true" ]; then
    echo "[restore-drill] step 2/3: keystore restore via soland-rotate-drill --import-only"
    cargo run --quiet --bin soland-rotate-drill -- \
        --import-only \
        --service-did "$SERVICE_DID" \
        --input "$WORKDIR/keystore.json"
else
    echo "[restore-drill] step 2/3: keystore restore skipped"
fi

# ── 3. walk multisig_pending and assert per-row aggregability ────────────
echo "[restore-drill] step 3/3: walk multisig_pending — per-row aggregability check"

ROWS_TOTAL=0
ROWS_OK=0
ROWS_BAD=0

while IFS= read -r line; do
    [ -z "$line" ] && continue
    ROWS_TOTAL=$((ROWS_TOTAL + 1))
    anchor_id="$(echo "$line" | jq -r '.anchor_id')"
    threshold_k="$(echo "$line" | jq -r '.threshold_k')"
    threshold_n="$(echo "$line" | jq -r '.threshold_n')"
    member_count="$(echo "$line" | jq -r '(.members // []) | length')"
    partial_count="$(echo "$line" | jq -r '(.partials // {}) | length')"
    canonical_len="$(echo "$line" | jq -r '(.canonical_b64 // "") | length')"
    claim_seq="$(echo "$line" | jq -r '.claim_seq // 0')"
    claimed_by="$(echo "$line" | jq -r '.claimed_by_node_id // ""')"
    claimed_until="$(echo "$line" | jq -r '.claimed_until // ""')"

    bad_reason=""

    # Threshold arithmetic invariant: 1 <= k <= n.
    if ! [ "$threshold_k" -ge 1 ] 2>/dev/null || \
       ! [ "$threshold_n" -ge "$threshold_k" ] 2>/dev/null; then
        bad_reason="threshold arithmetic violated (k=$threshold_k n=$threshold_n)"
    fi

    # members[] cardinality must match threshold_n.
    if [ -z "$bad_reason" ] && [ "$member_count" -ne "$threshold_n" ]; then
        bad_reason="members[] cardinality $member_count != threshold_n $threshold_n"
    fi

    # Every key in partials{} must appear in members[] (no orphaned partials).
    if [ -z "$bad_reason" ]; then
        orphans="$(echo "$line" | jq -r '
            (.partials // {} | keys) - (.members // [])
            | join(",")
        ')"
        if [ -n "$orphans" ]; then
            bad_reason="orphan partials not in members[]: $orphans"
        fi
    fi

    # Each partial must carry signature_b64 + kid.
    if [ -z "$bad_reason" ]; then
        missing_fields="$(echo "$line" | jq -r '
            [.partials // {} | to_entries[]
             | select((.value.signature_b64 // "") == ""
                  or  (.value.kid // "") == "")
             | .key] | join(",")
        ')"
        if [ -n "$missing_fields" ]; then
            bad_reason="partials missing signature_b64/kid: $missing_fields"
        fi
    fi

    # claim_seq is monotonic + non-negative.
    if [ -z "$bad_reason" ] && [ "$claim_seq" -lt 0 ] 2>/dev/null; then
        bad_reason="negative claim_seq=$claim_seq"
    fi

    # Lease invariant: when claimed_by_node_id is set, claimed_until must
    # also be present.
    if [ -z "$bad_reason" ] && [ -n "$claimed_by" ] && [ -z "$claimed_until" ]; then
        bad_reason="claimed_by_node_id set but claimed_until is NULL"
    fi

    # canonical_b64 may be empty (smoke buffer pre-aggregation), so we
    # don't require it. partials may be < threshold_k (in-flight).
    # Threshold-met rows additionally require canonical_b64 non-empty:
    if [ -z "$bad_reason" ] && [ "$partial_count" -ge "$threshold_k" ] && \
       [ "$canonical_len" -eq 0 ]; then
        bad_reason="threshold met (partials=$partial_count >= k=$threshold_k) but canonical_b64 is empty"
    fi

    if [ -z "$bad_reason" ]; then
        ROWS_OK=$((ROWS_OK + 1))
        printf "  PASS  %s  (k=%s/n=%s partials=%s claim_seq=%s)\n" \
            "$anchor_id" "$threshold_k" "$threshold_n" "$partial_count" "$claim_seq"
    else
        ROWS_BAD=$((ROWS_BAD + 1))
        printf "  FAIL  %s  %s\n" "$anchor_id" "$bad_reason"
    fi
done <"$WORKDIR/multisig_pending.jsonl"

# ── final summary ────────────────────────────────────────────────────────
if [ "$ROWS_BAD" -eq 0 ]; then
    echo "[restore-drill] RESTORE PASS  rows_total=$ROWS_TOTAL rows_ok=$ROWS_OK rows_bad=$ROWS_BAD"
    exit 0
else
    echo "[restore-drill] RESTORE FAIL  rows_total=$ROWS_TOTAL rows_ok=$ROWS_OK rows_bad=$ROWS_BAD"
    exit 1
fi
