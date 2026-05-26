#!/usr/bin/env bash
# soland production backup drill.
#
# Captures three artifacts into a single tarball with a manifest that
# pins per-artifact checksums:
#   1. `pg_dump` of the soland database (custom `Fc` format).
#   2. Snapshot of the keystore-persisted anchorer signing seed (when
#      `SOLAND_USE_KEYSTORE=true`). Implemented via `soland-rotate-drill
#      --export-only` so we can use the same KeyStore trait the running
#      server uses (no out-of-band keychain probing).
#   3. The `multisig_pending` table's full state (rows + claim_seq +
#      partials), exported as JSONL, so the restore drill can walk
#      every row and assert its aggregability post-restore.
#
# Honours the existing PASION_* / SOLAND_* env conventions:
#   - `DATABASE_URL` (or `PASION_DATABASE_URL` as override)
#   - `SOLAND_SERVICE_DID` — used to scope the keystore lookup
#   - `SOLAND_USE_KEYSTORE` — when "true", export the platform keystore seed
#   - `SOLAND_BACKUP_DIR`  — where the output tarball is written
#                             (defaults to ./backups/soland-<ts>.tar.gz)
#
# Exit codes:
#   0 success;  1 invariant/IO failure;  2 prerequisite missing.

set -euo pipefail

DRILL_TS="$(date -u +%Y%m%dT%H%M%SZ)"
WORKDIR="$(mktemp -d -t soland-backup-XXXXXX)"
trap 'rm -rf "$WORKDIR"' EXIT

DATABASE_URL="${PASION_DATABASE_URL:-${DATABASE_URL:-}}"
SERVICE_DID="${SOLAND_SERVICE_DID:-did:web:soland.local}"
USE_KEYSTORE="${SOLAND_USE_KEYSTORE:-false}"
BACKUP_DIR="${SOLAND_BACKUP_DIR:-./backups}"
mkdir -p "$BACKUP_DIR"
OUTPUT="${BACKUP_DIR}/soland-${DRILL_TS}.tar.gz"

if [ -z "$DATABASE_URL" ]; then
    echo "[backup-drill] FATAL: DATABASE_URL (or PASION_DATABASE_URL) is unset" >&2
    exit 2
fi

for cmd in pg_dump psql sha256sum tar jq; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "[backup-drill] FATAL: missing prerequisite '$cmd'" >&2
        exit 2
    fi
done

echo "[backup-drill] timestamp=$DRILL_TS service_did=$SERVICE_DID workdir=$WORKDIR"

# ── 1. pg_dump ───────────────────────────────────────────────────────────
DUMP_PATH="${WORKDIR}/soland-database.dump"
echo "[backup-drill] step 1/3: pg_dump custom-format"
pg_dump --format=custom --no-owner --no-acl --file="$DUMP_PATH" "$DATABASE_URL"
DUMP_SHA="$(sha256sum "$DUMP_PATH" | awk '{print $1}')"
echo "[backup-drill]   sha256=$DUMP_SHA"

# ── 2. keystore snapshot ─────────────────────────────────────────────────
KEYSTORE_PATH="${WORKDIR}/keystore.json"
if [ "$USE_KEYSTORE" = "true" ]; then
    echo "[backup-drill] step 2/3: keystore export via soland-rotate-drill --export-only"
    cargo run --quiet --bin soland-rotate-drill -- \
        --export-only \
        --service-did "$SERVICE_DID" \
        --output "$KEYSTORE_PATH"
else
    echo "[backup-drill] step 2/3: keystore export skipped (SOLAND_USE_KEYSTORE != true)"
    cat >"$KEYSTORE_PATH" <<EOF
{ "skipped": true, "reason": "SOLAND_USE_KEYSTORE is not 'true'" }
EOF
fi
KEYSTORE_SHA="$(sha256sum "$KEYSTORE_PATH" | awk '{print $1}')"
echo "[backup-drill]   sha256=$KEYSTORE_SHA"

# ── 3. multisig_pending state ────────────────────────────────────────────
MULTISIG_PATH="${WORKDIR}/multisig_pending.jsonl"
echo "[backup-drill] step 3/3: multisig_pending JSONL export"
psql --quiet --tuples-only --no-align "$DATABASE_URL" >"$MULTISIG_PATH" <<'SQL'
SELECT json_build_object(
    'anchor_id',          anchor_id,
    'space_id',           space_id,
    'threshold_k',        threshold_k,
    'threshold_n',        threshold_n,
    'members',            members,
    'canonical_b64',      canonical_b64,
    'partials',           partials,
    'created_at',         to_char(created_at AT TIME ZONE 'UTC',
                                   'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
    'expires_at',         to_char(expires_at AT TIME ZONE 'UTC',
                                   'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
    'claimed_by_node_id', claimed_by_node_id,
    'claimed_until',      CASE
                              WHEN claimed_until IS NULL THEN NULL
                              ELSE to_char(claimed_until AT TIME ZONE 'UTC',
                                            'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
                          END,
    'claim_seq',          claim_seq
)::text
FROM multisig_pending
ORDER BY anchor_id;
SQL
MULTISIG_ROW_COUNT="$(wc -l <"$MULTISIG_PATH" | awk '{print $1}')"
MULTISIG_SHA="$(sha256sum "$MULTISIG_PATH" | awk '{print $1}')"
echo "[backup-drill]   rows=$MULTISIG_ROW_COUNT sha256=$MULTISIG_SHA"

# ── manifest ─────────────────────────────────────────────────────────────
MANIFEST_PATH="${WORKDIR}/manifest.json"
jq -n \
    --arg ts "$DRILL_TS" \
    --arg did "$SERVICE_DID" \
    --arg use_ks "$USE_KEYSTORE" \
    --arg dump_sha "$DUMP_SHA" \
    --arg ks_sha "$KEYSTORE_SHA" \
    --arg mp_sha "$MULTISIG_SHA" \
    --argjson mp_rows "$MULTISIG_ROW_COUNT" \
    '{
        manifest_version: "1",
        produced_by: "soland/scripts/backup-drill.sh",
        timestamp: $ts,
        service_did: $did,
        use_keystore: $use_ks,
        artifacts: {
            "soland-database.dump":  { sha256: $dump_sha, kind: "pg_dump_custom" },
            "keystore.json":         { sha256: $ks_sha, kind: "keystore_seed" },
            "multisig_pending.jsonl":{ sha256: $mp_sha, kind: "multisig_pending_jsonl",
                                       row_count: $mp_rows }
        }
    }' >"$MANIFEST_PATH"
MANIFEST_SHA="$(sha256sum "$MANIFEST_PATH" | awk '{print $1}')"
echo "[backup-drill] manifest sha256=$MANIFEST_SHA"

# ── tarball ──────────────────────────────────────────────────────────────
tar -czf "$OUTPUT" \
    -C "$WORKDIR" \
    manifest.json \
    soland-database.dump \
    keystore.json \
    multisig_pending.jsonl

OUTPUT_SHA="$(sha256sum "$OUTPUT" | awk '{print $1}')"
echo "[backup-drill] OK -> $OUTPUT"
echo "[backup-drill] tarball sha256=$OUTPUT_SHA"
