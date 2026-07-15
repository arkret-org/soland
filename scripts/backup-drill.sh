#!/usr/bin/env bash
# soland production backup drill.
#
# Captures four artifacts into a single tarball with a manifest that
# pins per-artifact checksums:
#   1. `pg_dump` of the soland database (custom `Fc` format).
#   2. SDK service-identity bundle containing public recovery evidence and
#      opaque KeyRefs (never secret material).
#   3. Snapshot of the keystore-persisted notary signing seed. Implemented via `soland-rotate-drill
#      --export-only` so we can use the same KeyStore trait the running
#      server uses (no out-of-band keychain probing).
#   4. The `multisig_pending` table's full state (rows + claim_seq +
#      partials), exported as JSONL, so the restore drill can walk
#      every row and assert its aggregability post-restore.
#
# Honours the existing SOLAND_* env conventions:
#   - `SOLAND_DATABASE_URL` or `DATABASE_URL`
#   - `SOLAND_SERVICE_IDENTITY_BUNDLE_DIR` — SDK identity-bundle backend
#   - `SOLAND_KEYSTORE_BACKEND` — durable backend used by the running server
#   - `SOLAND_BACKUP_DIR`  — where the output tarball is written
#                             (defaults to ./backups/soland-<ts>.tar.gz)
#
# Exit codes:
#   0 success;  1 invariant/IO failure;  2 prerequisite missing.

set -euo pipefail

DRILL_TS="$(date -u +%Y%m%dT%H%M%SZ)"
WORKDIR="$(mktemp -d -t soland-backup-XXXXXX)"
trap 'rm -rf "$WORKDIR"' EXIT

DATABASE_URL="${SOLAND_DATABASE_URL:-${DATABASE_URL:-${PASION_DATABASE_URL:-}}}"
BUNDLE_DIR="${SOLAND_SERVICE_IDENTITY_BUNDLE_DIR:-}"
KEYSTORE_BACKEND="${SOLAND_KEYSTORE_BACKEND:-}"
BACKUP_DIR="${SOLAND_BACKUP_DIR:-./backups}"
mkdir -p "$BACKUP_DIR"
OUTPUT="${BACKUP_DIR}/soland-${DRILL_TS}.tar.gz"

if [ -z "$DATABASE_URL" ]; then
    echo "[backup-drill] FATAL: SOLAND_DATABASE_URL or DATABASE_URL is unset" >&2
    exit 2
fi
if [ -z "$BUNDLE_DIR" ] || [ ! -d "$BUNDLE_DIR" ]; then
    echo "[backup-drill] FATAL: SOLAND_SERVICE_IDENTITY_BUNDLE_DIR must name the initialized SDK bundle directory" >&2
    exit 2
fi
case "$KEYSTORE_BACKEND" in
    platform|encrypted_file) ;;
    *)
        echo "[backup-drill] FATAL: SOLAND_KEYSTORE_BACKEND must be platform or encrypted_file" >&2
        exit 2
        ;;
esac

for cmd in pg_dump psql sha256sum tar jq; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "[backup-drill] FATAL: missing prerequisite '$cmd'" >&2
        exit 2
    fi
done

mapfile -d '' BUNDLE_CANDIDATES < <(find "$BUNDLE_DIR" -maxdepth 1 -type f -name '*.json' -print0)
if [ "${#BUNDLE_CANDIDATES[@]}" -ne 1 ]; then
    echo "[backup-drill] FATAL: expected exactly one SDK identity bundle in $BUNDLE_DIR; found ${#BUNDLE_CANDIDATES[@]}" >&2
    exit 2
fi
BUNDLE_SOURCE="${BUNDLE_CANDIDATES[0]}"
BUNDLE_BACKEND_FILE="$(basename "$BUNDLE_SOURCE")"
BUNDLE_PATH="${WORKDIR}/service-identity-bundle.json"
cp "$BUNDLE_SOURCE" "$BUNDLE_PATH"
SERVICE_ID="$(jq -er '.identity.identity.service_id | select(startswith("did:webvh:"))' "$BUNDLE_PATH")" || {
    echo "[backup-drill] FATAL: SDK identity bundle has no did:webvh service_id" >&2
    exit 1
}
BUNDLE_SHA="$(sha256sum "$BUNDLE_PATH" | awk '{print $1}')"

echo "[backup-drill] timestamp=$DRILL_TS service_id=$SERVICE_ID workdir=$WORKDIR"
echo "[backup-drill] identity bundle=$BUNDLE_BACKEND_FILE sha256=$BUNDLE_SHA"

# ── 1. pg_dump ───────────────────────────────────────────────────────────
DUMP_PATH="${WORKDIR}/soland-database.dump"
echo "[backup-drill] step 1/4: pg_dump custom-format"
pg_dump --format=custom --no-owner --no-acl --file="$DUMP_PATH" "$DATABASE_URL"
DUMP_SHA="$(sha256sum "$DUMP_PATH" | awk '{print $1}')"
echo "[backup-drill]   sha256=$DUMP_SHA"

# ── 2. identity bundle ───────────────────────────────────────────────────
echo "[backup-drill] step 2/4: SDK identity bundle captured"

# ── 3. keystore snapshot ─────────────────────────────────────────────────
KEYSTORE_PATH="${WORKDIR}/keystore.json"
echo "[backup-drill] step 3/4: keystore export via soland-rotate-drill --export-only"
cargo run --quiet --bin soland-rotate-drill -- \
    --export-only \
    --identity-bundle "$BUNDLE_PATH" \
    --output "$KEYSTORE_PATH"
KEYSTORE_SHA="$(sha256sum "$KEYSTORE_PATH" | awk '{print $1}')"
echo "[backup-drill]   sha256=$KEYSTORE_SHA"

# ── 4. multisig_pending state ────────────────────────────────────────────
MULTISIG_PATH="${WORKDIR}/multisig_pending.jsonl"
echo "[backup-drill] step 4/4: multisig_pending JSONL export"
psql --quiet --tuples-only --no-align "$DATABASE_URL" >"$MULTISIG_PATH" <<'SQL'
SELECT json_build_object(
    'seal_id',            id,
    'realm_id',           realm_id,
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
ORDER BY id;
SQL
MULTISIG_ROW_COUNT="$(wc -l <"$MULTISIG_PATH" | awk '{print $1}')"
MULTISIG_SHA="$(sha256sum "$MULTISIG_PATH" | awk '{print $1}')"
echo "[backup-drill]   rows=$MULTISIG_ROW_COUNT sha256=$MULTISIG_SHA"

# ── manifest ─────────────────────────────────────────────────────────────
MANIFEST_PATH="${WORKDIR}/manifest.json"
jq -n \
    --arg ts "$DRILL_TS" \
    --arg did "$SERVICE_ID" \
    --arg bundle_backend_file "$BUNDLE_BACKEND_FILE" \
    --arg keystore_backend "$KEYSTORE_BACKEND" \
    --arg dump_sha "$DUMP_SHA" \
    --arg bundle_sha "$BUNDLE_SHA" \
    --arg ks_sha "$KEYSTORE_SHA" \
    --arg mp_sha "$MULTISIG_SHA" \
    --argjson mp_rows "$MULTISIG_ROW_COUNT" \
    '{
        manifest_version: "1",
        produced_by: "soland/scripts/backup-drill.sh",
        timestamp: $ts,
        service_id: $did,
        identity_bundle_backend_file: $bundle_backend_file,
        keystore_backend: $keystore_backend,
        artifacts: {
            "soland-database.dump":  { sha256: $dump_sha, kind: "pg_dump_custom" },
            "service-identity-bundle.json": { sha256: $bundle_sha,
                                               kind: "arkret_service_identity_bundle" },
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
    service-identity-bundle.json \
    keystore.json \
    multisig_pending.jsonl

OUTPUT_SHA="$(sha256sum "$OUTPUT" | awk '{print $1}')"
echo "[backup-drill] OK -> $OUTPUT"
echo "[backup-drill] tarball sha256=$OUTPUT_SHA"
