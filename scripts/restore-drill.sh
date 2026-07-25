#!/usr/bin/env bash
# soland production restore drill.
#
# Inverse of `backup-drill.sh`. Accepts a tarball produced by that script,
# restores the database + keystore, then walks every row in
# `multisig_pending` and asserts each is still aggregable.

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

DATABASE_URL="${SOLAND_DATABASE_URL:-${DATABASE_URL:-${PASION_DATABASE_URL:-}}}"
BUNDLE_DIR="${SOLAND_SERVICE_IDENTITY_BUNDLE_DIR:-}"
KEYSTORE_BACKEND="${SOLAND_KEYSTORE_BACKEND:-}"
WORKDIR="$(mktemp -d -t soland-restore-XXXXXX)"
trap 'rm -rf "$WORKDIR"' EXIT

if [ -z "$DATABASE_URL" ]; then
    echo "[restore-drill] FATAL: SOLAND_DATABASE_URL or DATABASE_URL is unset" >&2
    exit 2
fi
if [ -z "$BUNDLE_DIR" ]; then
    echo "[restore-drill] FATAL: SOLAND_SERVICE_IDENTITY_BUNDLE_DIR is unset" >&2
    exit 2
fi
case "$KEYSTORE_BACKEND" in
    platform|encrypted_file) ;;
    *)
        echo "[restore-drill] FATAL: SOLAND_KEYSTORE_BACKEND must be platform or encrypted_file" >&2
        exit 2
        ;;
esac

for cmd in pg_restore psql sha256sum tar jq; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "[restore-drill] FATAL: missing prerequisite '$cmd'" >&2
        exit 2
    fi
done

echo "[restore-drill] tarball=$TARBALL workdir=$WORKDIR"
tar -xzf "$TARBALL" -C "$WORKDIR"

MANIFEST="$WORKDIR/manifest.json"
if [ ! -f "$MANIFEST" ]; then
    echo "[restore-drill] FATAL: tarball missing manifest.json" >&2
    exit 1
fi

declare -A EXPECTED_SHA
while IFS=$'\t' read -r name sha; do
    EXPECTED_SHA[$name]="$sha"
done < <(jq -r '.artifacts | to_entries[] | "\(.key)\t\(.value.sha256)"' "$MANIFEST")

for name in soland-database.dump service-identity-bundle.json keystore.json multisig_pending.jsonl; do
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

BUNDLE_PATH="$WORKDIR/service-identity-bundle.json"
SERVICE_ID="$(jq -er '.identity.identity.service_id | select(startswith("did:webvh:"))' "$BUNDLE_PATH")" || {
    echo "[restore-drill] FATAL: identity bundle has no did:webvh service_id" >&2
    exit 1
}
MANIFEST_SERVICE_ID="$(jq -er '.service_id' "$MANIFEST")"
if [ "$SERVICE_ID" != "$MANIFEST_SERVICE_ID" ]; then
    echo "[restore-drill] FATAL: identity bundle service_id does not match manifest" >&2
    exit 1
fi
BUNDLE_BACKEND_FILE="$(jq -er '.identity_bundle_backend_file' "$MANIFEST")"
case "$BUNDLE_BACKEND_FILE" in
    ""|"."|".."|*/*|*\\*)
        echo "[restore-drill] FATAL: unsafe identity_bundle_backend_file in manifest" >&2
        exit 1
        ;;
esac
MANIFEST_KEYSTORE_BACKEND="$(jq -er '.keystore_backend' "$MANIFEST")"
case "$MANIFEST_KEYSTORE_BACKEND" in
    platform|encrypted_file) ;;
    *)
        echo "[restore-drill] FATAL: backup manifest has unsupported keystore_backend=$MANIFEST_KEYSTORE_BACKEND" >&2
        exit 1
        ;;
esac
echo "[restore-drill] service_id=$SERVICE_ID identity_bundle_backend_file=$BUNDLE_BACKEND_FILE keystore_backend=$MANIFEST_KEYSTORE_BACKEND->$KEYSTORE_BACKEND"

echo "[restore-drill] step 1/4: pg_restore (clean+if-exists)"
pg_restore --clean --if-exists --no-owner --no-acl \
    --dbname="$DATABASE_URL" "$WORKDIR/soland-database.dump"

echo "[restore-drill] step 2/4: restore SDK identity bundle"
mkdir -p "$BUNDLE_DIR"
cp "$BUNDLE_PATH" "$BUNDLE_DIR/$BUNDLE_BACKEND_FILE"

echo "[restore-drill] step 3/4: keystore restore via soland-keystore-snapshot --import-only"
cargo run --quiet --bin soland-keystore-snapshot -- \
    --import-only \
    --identity-bundle "$BUNDLE_PATH" \
    --input "$WORKDIR/keystore.json"

echo "[restore-drill] step 4/4: walk multisig_pending - per-row aggregability check"

ROWS_TOTAL=0
ROWS_OK=0
ROWS_BAD=0

while IFS= read -r line; do
    [ -z "$line" ] && continue
    ROWS_TOTAL=$((ROWS_TOTAL + 1))
    seal_id="$(echo "$line" | jq -r '.seal_id')"
    threshold_k="$(echo "$line" | jq -r '.threshold_k')"
    threshold_n="$(echo "$line" | jq -r '.threshold_n')"
    member_count="$(echo "$line" | jq -r '(.members // []) | length')"
    partial_count="$(echo "$line" | jq -r '(.partials // {}) | length')"
    canonical_len="$(echo "$line" | jq -r '(.canonical_b64 // "") | length')"
    claim_seq="$(echo "$line" | jq -r '.claim_seq // 0')"
    claimed_by="$(echo "$line" | jq -r '.claimed_by_node_id // ""')"
    claimed_until="$(echo "$line" | jq -r '.claimed_until // ""')"

    bad_reason=""

    if ! [ "$threshold_k" -ge 1 ] 2>/dev/null || \
       ! [ "$threshold_n" -ge "$threshold_k" ] 2>/dev/null; then
        bad_reason="threshold arithmetic violated (k=$threshold_k n=$threshold_n)"
    fi

    if [ -z "$bad_reason" ] && [ "$member_count" -ne "$threshold_n" ]; then
        bad_reason="members[] cardinality $member_count != threshold_n $threshold_n"
    fi

    if [ -z "$bad_reason" ]; then
        orphans="$(echo "$line" | jq -r '
            (.partials // {} | keys) - (.members // [])
            | join(",")
        ')"
        if [ -n "$orphans" ]; then
            bad_reason="orphan partials not in members[]: $orphans"
        fi
    fi

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

    if [ -z "$bad_reason" ] && [ "$claim_seq" -lt 0 ] 2>/dev/null; then
        bad_reason="negative claim_seq=$claim_seq"
    fi

    if [ -z "$bad_reason" ] && [ -n "$claimed_by" ] && [ -z "$claimed_until" ]; then
        bad_reason="claimed_by_node_id set but claimed_until is NULL"
    fi

    if [ -z "$bad_reason" ] && [ "$partial_count" -ge "$threshold_k" ] && \
       [ "$canonical_len" -eq 0 ]; then
        bad_reason="threshold met (partials=$partial_count >= k=$threshold_k) but canonical_b64 is empty"
    fi

    if [ -z "$bad_reason" ]; then
        ROWS_OK=$((ROWS_OK + 1))
        printf "  PASS  %s  (k=%s/n=%s partials=%s claim_seq=%s)\n" \
            "$seal_id" "$threshold_k" "$threshold_n" "$partial_count" "$claim_seq"
    else
        ROWS_BAD=$((ROWS_BAD + 1))
        printf "  FAIL  %s  %s\n" "$seal_id" "$bad_reason"
    fi
done <"$WORKDIR/multisig_pending.jsonl"

if [ "$ROWS_BAD" -eq 0 ]; then
    echo "[restore-drill] RESTORE PASS  rows_total=$ROWS_TOTAL rows_ok=$ROWS_OK rows_bad=$ROWS_BAD"
    exit 0
fi

echo "[restore-drill] RESTORE FAIL  rows_total=$ROWS_TOTAL rows_ok=$ROWS_OK rows_bad=$ROWS_BAD"
exit 1
