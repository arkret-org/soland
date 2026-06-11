# Deploying soland

Production guidance for running soland as a single-process Cokret v1 reference
server. soland is pre-1.0 — review [_todos.md](_todos.md) for the open scaffold
endpoints (push outbound, MIMI provider directory and directory discovery)
before serving real users.

## Prerequisites

| Component | Recommended | Notes |
| --- | --- | --- |
| OS | Linux (Debian/Ubuntu LTS) | Other targets are CI-tested but less battle-hardened |
| PostgreSQL | 16+ | `pq-src` builds libpq inline; the runtime image only needs the network reachability |
| Reverse proxy | nginx, Caddy, or Traefik | TLS termination is **expected** to live in the reverse proxy, not soland itself |
| Object storage | local volume or S3-compatible bucket | Local disk is fine for one node; production should prefer S3/MinIO/R2-style object storage |
| Container runtime | Docker / containerd / Podman | Build or load the image locally; this readiness workflow does not push registry images or tags |

## 1. Provision PostgreSQL

```sql
CREATE ROLE soland WITH LOGIN PASSWORD '<strong-random-password>';
CREATE DATABASE soland OWNER soland;
GRANT ALL PRIVILEGES ON DATABASE soland TO soland;
```

soland runs Diesel migrations on startup; no manual DDL is required.

## 2. Configure environment

Create a deploy-time `.env` (or a Kubernetes Secret / systemd EnvironmentFile):

```dotenv
SOLAND_BIND=0.0.0.0:8698
SOLAND_PUBLIC_BASE_URL=https://soland.example
SOLAND_TLS_CERT_PATH=/etc/soland/tls/fullchain.pem
SOLAND_TLS_KEY_PATH=/etc/soland/tls/privkey.pem
SOLAND_SERVICE_DID=did:web:soland.example
SOLAND_EMBEDDED_WEBVH_PROVIDER_ENABLED=true
SOLAND_EMBEDDED_WEBVH_REGISTRATION_BEARER=<shared-secret-configured-in-coauth>
# Optional: use a standalone webvh provider instead of, or alongside, the embedded provider.
# SOLAND_EXTERNAL_WEBVH_PROVIDER_URL=https://webvh.example
# SOLAND_DEFAULT_WEBVH_PROVIDER_ID=soland.embedded
SOLAND_OAUTH_INTROSPECTION_URL=https://coauth.example/oauth2/introspect
SOLAND_OAUTH_INTROSPECTION_BEARER=<shared-secret-configured-in-coauth>
SOLAND_OBJECT_STORAGE_BACKEND=s3-compatible
SOLAND_OBJECT_STORAGE_S3_BUCKET=soland
SOLAND_OBJECT_STORAGE_S3_REGION=us-east-1
SOLAND_OBJECT_STORAGE_S3_ENDPOINT=https://s3.example.com
SOLAND_OBJECT_STORAGE_S3_ACCESS_KEY_ID=<access-key>
SOLAND_OBJECT_STORAGE_S3_SECRET_ACCESS_KEY=<secret-key>
SOLAND_OBJECT_STORAGE_S3_FORCE_PATH_STYLE=true
SOLAND_OBJECT_STORAGE_PREFIX=prod
SOLAND_CORS_ALLOW_ORIGIN=https://app.example
SOLAND_MAX_REQUEST_SIZE=1048576
DATABASE_URL=postgres://soland:<password>@db.internal:5432/soland?sslmode=verify-full

# `SOLAND_DEVELOPMENT_MODE` is unset (defaults to false). Enabling it in
# production exposes `dev_login`, the admin snapshot endpoints, and a relaxed
# DID-document validation path — never set this in a real deploy.

RUST_LOG=soland=info,salvo=info,warn
```

`SOLAND_MAX_REQUEST_SIZE` is parsed as bytes. Leave it unset for the default
1 MiB body cap; requests above the cap return `413 Payload Too Large` before
the route handler reads JSON or form data.

### Advanced environment reference

Most deployments only need the variables in the sample above. The table below
lists the remaining runtime variables soland reads, including security-sensitive
and rollout-only switches that should be managed deliberately.

| Variable | Default | Purpose |
| --- | --- | --- |
| `SOLAND_ACCOUNTABLE_PRINCIPALS_STRICT_REJECT` | unset | Reject legacy accountable-principal payloads instead of accepting with compatibility handling. |
| `SOLAND_ADMIN_PAGE_LIMIT` | `100` | Default admin API page size. |
| `SOLAND_ADMIN_MAX_PAGE_LIMIT` | `1000` | Maximum admin API page size; clamped above the default. |
| `SOLAND_AGENT_AUDIT_BINDING_SIGNING_SEED` | ephemeral seed | Optional base64 ed25519 seed for agent audit-binding signatures; store and rotate like other signing keys. |
| `SOLAND_COMPACTION_MIN_ANCHOR_AGE_SECS` | `604800` | Minimum seal age before compaction pruning may consider it. |
| `SOLAND_COMPACTION_MIN_WITNESSES` | `1` | Minimum compaction witnesses required before pruning. |
| `SOLAND_COMPACTION_PRESERVE_GENESIS` | `true` | Preserve genesis seals during compaction pruning. |
| `SOLAND_COMPACTION_PRUNE_ONLY_SINGLETON_SUCCESSORS` | `true` | Restrict pruning to singleton-successor seal chains. |
| `SOLAND_COMPACTION_PRUNE_WALK_PER_REALM_LIMIT` | `50` | Maximum pruning candidates examined per realm walk. |
| `SOLAND_DID_RESOLVER_ALLOW_METHODS` | `web,key,uuid` | Comma-separated DID methods accepted by outbound DID resolution. |
| `SOLAND_ENABLE_CONFORMANCE_ENDPOINTS` | unset | Enables local conformance helper endpoints; keep unset in production. |
| `SOLAND_ERASURE_PROPAGATION_WINDOW_MS` | `604800000` | Erasure receipt propagation window. |
| `SOLAND_EXTERNAL_WEBVH_PROVIDER_SERVICE_DID` | unset | Expected service DID when probing `SOLAND_EXTERNAL_WEBVH_PROVIDER_URL`. |
| `SOLAND_EXTERNAL_WEBVH_PROVIDER_TRUST_DOMAIN` | derived trust domain | Expected trust domain for the external webvh provider probe. |
| `SOLAND_FEDERATION_POLICY` | `mesh` | Federation policy mode (`mesh` or `hub`). |
| `SOLAND_HEALTHCHECK_URL` | derived from `SOLAND_BIND` | URL used by the built-in healthcheck command. |
| `SOLAND_JWS_REPLAY_WINDOW_SECONDS` | `300` | Accepted JWS replay window; `0` disables replay-window enforcement. |
| `SOLAND_KEY_BACKUP_DAILY_DOWNLOAD_LIMIT` | spec default | Per-principal daily key-backup download limit. |
| `SOLAND_MEDIA_SERVICE_LEGACY_REJECT` | unset | Reject legacy realm media-service payloads instead of compatibility handling. |
| `SOLAND_OBJECT_STORAGE_S3_SESSION_TOKEN` | unset | Optional S3 session token for temporary credentials. |
| `SOLAND_OBJECT_STORAGE_S3_SKIP_SIGNATURE` | `false` | Skip S3 request signing for test-only object stores; do not enable for production S3. |
| `SOLAND_PROFILE_STATELESS_CURSOR` | unset | Advertise and allow the stateless cursor profile. |
| `SOLAND_PUSH_BRIDGE_CACHE_TTL_SECS` | `900` | TTL for push bridge trust/cache entries. |
| `SOLAND_PUSH_BRIDGE_TRUSTED_SERVICE_DIDS` | empty | Comma-separated service DIDs trusted for push bridge elevation. |
| `SOLAND_RATE_LIMIT_TRUST_X_FORWARDED_FOR` | `false` | Trust `X-Forwarded-For` for rate limiting when behind a trusted proxy. |
| `SOLAND_TRUST_X_FORWARDED_FOR` | `false` | Backward-compatible alias for `SOLAND_RATE_LIMIT_TRUST_X_FORWARDED_FOR`. |
| `SOLAND_RESUMABLE_UPLOAD_DIR` | `./soland-resumable-uploads` | Directory for resumable-upload staging files. |
| `SOLAND_RESUMABLE_UPLOAD_TTL_SECS` | `86400` | Incomplete resumable-upload TTL; minimum 60 seconds. |
| `SOLAND_SOVEREIGN_ENCLAVE` | `false` | Enables the sovereign-enclave profile and startup invariant checks. |
| `SOLAND_SOVEREIGN_ENCLAVE_ALLOWED_OUTBOUND_HOSTS` | empty | Comma-separated outbound host allow-list for sovereign-enclave deployments. |
| `SOLAND_VERIFIED_PROFILES_ARTIFACT` | unset | Path to a cotest `verified-profiles.json` artifact to advertise verified profiles. |

Validate the env block on the target host once:

```bash
soland --bind "${SOLAND_BIND}" --help    # cheap startup sanity check
```

## 3. Run the binary

### systemd unit

```ini
[Unit]
Description=soland — Cokret v1 principal server
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
Type=simple
User=soland
Group=soland
EnvironmentFile=/etc/soland/soland.env
ExecStart=/usr/local/bin/soland
WorkingDirectory=/var/lib/soland
StateDirectory=soland
Restart=on-failure
RestartSec=2s
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/soland
ProtectHome=yes

[Install]
WantedBy=multi-user.target
```

soland traps `SIGINT` / `SIGTERM` and runs Salvo's graceful shutdown, so
`systemctl stop` (or `docker stop` / Kubernetes pod termination) drains
in-flight requests before exiting.

### Docker

```bash
docker run --name soland --restart=always -d \
  -p 127.0.0.1:8698:8698 \
  -e SOLAND_BIND=0.0.0.0:8698 \
  -e SOLAND_PUBLIC_BASE_URL=https://soland.example \
  -e SOLAND_SERVICE_DID=did:web:soland.example \
  -e SOLAND_OAUTH_INTROSPECTION_URL=https://coauth.example/oauth2/introspect \
  -e SOLAND_OAUTH_INTROSPECTION_BEARER=<shared-secret-configured-in-coauth> \
  -e DATABASE_URL=postgres://soland:<password>@db:5432/soland?sslmode=verify-full \
  -e SOLAND_OBJECT_STORAGE_BACKEND=filesystem \
  -e SOLAND_OBJECT_STORAGE_LOCAL_ROOT=/var/lib/soland/objects \
  -e RUST_LOG=soland=info \
  -v soland-objects:/var/lib/soland \
  ghcr.io/cokret/soland:<tag>
```

The image runs as UID `10001`. Mounted volumes for
`SOLAND_OBJECT_STORAGE_LOCAL_ROOT` must be chowned to that UID (or use a named
Docker volume so Docker handles it). S3-compatible backends do not need a media
volume.

### Helm

The production chart lives at `deploy/helm/soland`. Render it before applying
so secrets and network ranges are explicit in the release artifact:

```bash
helm template soland ./deploy/helm/soland \
  --namespace cokret \
  --set image.tag=<tag> \
  --set env.SOLAND_PUBLIC_BASE_URL=https://soland.example \
  --set env.SOLAND_SERVICE_DID=did:web:soland.example \
  --set secretEnv.DATABASE_URL='postgres://soland:<password>@db.internal:5432/soland?sslmode=verify-full' \
  --set secretEnv.SOLAND_OAUTH_INTROSPECTION_URL=https://coauth.example/oauth2/introspect \
  --set secretEnv.SOLAND_OAUTH_INTROSPECTION_BEARER='<shared-secret-configured-in-coauth>'
```

Install the same values with:

```bash
helm upgrade --install soland ./deploy/helm/soland \
  --namespace cokret --create-namespace \
  -f production-values.yaml
```

For production, set `networkPolicy.enabled=true` and provide
`networkPolicy.egress.databaseCidrs`, `objectStorageCidrs`, and `oauthCidrs`
for the actual PostgreSQL, S3-compatible object storage, and coauth
introspection endpoints. Leave `SOLAND_DEVELOPMENT_MODE` unset; the chart
does not set it by default.

## 4. Front with TLS

soland speaks plaintext HTTP — terminate TLS in the reverse proxy.

Caddy example:

```caddyfile
soland.example {
    encode zstd gzip

    @api {
        path /api/* /.well-known/* /health
    }
    handle @api {
        reverse_proxy 127.0.0.1:8698 {
            header_up X-Forwarded-Proto {scheme}
            header_up X-Forwarded-For {remote_host}
        }
    }
}
```

Make sure the proxy passes the `Authorization`, `X-Cokret-Wait-For`,
`X-Cokret-SHA256`, and `Range` request headers; soland sends back
`Retry-After`, `X-Cokret-Wait-For-Satisfied`, `Content-Range`, and
`Accept-Ranges`.

## 5. Health checks

The `/health` endpoint returns a small JSON envelope plus
`200 OK` (or `503 Service Unavailable` when the database / persistence probe
fails).

Docker:

```dockerfile
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS http://localhost:8698/health || exit 1
```

Kubernetes:

```yaml
livenessProbe:
  httpGet:
    path: /health
    port: 8698
  initialDelaySeconds: 10
  periodSeconds: 30
readinessProbe:
  httpGet:
    path: /readyz
    port: 8698
  initialDelaySeconds: 5
  periodSeconds: 10
```

`/readyz` returns `503` until the database probe succeeds, boot migrations have
completed, configured introspection bearers are present, and any configured
external webvh provider has passed the startup `/describe` probe.

## 6. Backups

| Object | What to back up | How |
| --- | --- | --- |
| PostgreSQL | All tables | `pg_dump` daily, plus continuous WAL archiving for point-in-time recovery |
| Object storage bucket/volume | Uploaded media | enable bucket versioning or snapshot the local volume on the same cadence as the database; align so blob references in the DB stay resolvable |
| `SOLAND_SERVICE_DID` material | DID rotation history | Out of scope — manage via the DID method (`did:web` vs `did:plc`) |

Restore order: stop soland → restore DB → restore object storage bucket/volume → start soland.
The startup migrations are idempotent.

## 7. Observability

soland emits structured `tracing` events with stable `event` and `worker`
fields for process lifecycle and background tasks. It also exposes
Prometheus text metrics on a separate listener:

```dotenv
SOLAND_METRICS_BIND=127.0.0.1:9090
```

Scrape `http://127.0.0.1:9090/metrics` for:

- `soland_request_total{op,status}`
- `soland_request_duration_seconds` histogram buckets
- `soland_db_pool_in_use`
- `soland_federation_outbox_depth`
- `soland_federation_outbox_dead_letter_total` (P5 — counter; alert on
  any non-zero rate over 5m via `examples/prometheus-alerts.yml`)
- `soland_audit_append_failures_total` (alert on any non-zero rate over
  5m — see `examples/prometheus-alerts.yml`)

A copy-pasteable `prometheus-alerts.yml` lives under `examples/`; load
it via Prometheus' `rule_files:` directive.

### Structured JSON logging

Production deployments default to **JSON logs** when
`SOLAND_DEVELOPMENT_MODE=false` (the default). One log line per event,
keyed by the standard `tracing` span / field set, ready for ingestion
by Loki / OpenSearch / Cloud Logging without a bespoke parser. Force
the format explicitly with `SOLAND_LOG_FORMAT=json|plain`. The
runbook log-search recipes in `docs/runbook.md` assume the JSON shape.

OpenTelemetry tracing is build-time opt-in so ordinary local runs do not pull
an exporter:

```powershell
cargo run --features otel -- --bind 127.0.0.1:8698
```

Enable OTLP export at runtime:

```dotenv
SOLAND_OTEL_EXPORTER=otlp
SOLAND_OTEL_ENDPOINT=http://otel-collector:4317
SOLAND_OTEL_SERVICE_NAME=soland
SOLAND_OTEL_SAMPLE_RATIO=1.0
SOLAND_OTEL_TIMEOUT_SECS=3
```

Remaining roadmap before 1.0:

- per-handler `instrument` spans carrying `actor / space / event_kind`

Set `RUST_LOG=soland=debug,salvo=info,warn` in production-like environments
while closing 1.0 readiness. Keep `SOLAND_LOG_FILE` pointed at a durable path
when running under a supervisor that buffers stdout.

Alert on:

- `200 /health` request rate dropping below the configured threshold
- 5xx error rate over rolling 5-minute windows
- `auth.dev_login` audit events outside the development environment (this
  should be impossible with `SOLAND_DEVELOPMENT_MODE=false`, but alert
  belt-and-braces)

### Local observability and rate-limit examples

Minimal local metrics-only run:

```dotenv
SOLAND_BIND=127.0.0.1:8698
SOLAND_METRICS_BIND=127.0.0.1:9090
RUST_LOG=soland=info,salvo=warn
```

OTLP trace export run:

```powershell
$env:SOLAND_OTEL_EXPORTER="otlp"
$env:SOLAND_OTEL_ENDPOINT="http://127.0.0.1:4317"
$env:SOLAND_OTEL_SAMPLE_RATIO="0.25"
cargo run --features otel -- --bind 127.0.0.1:8698
```

Single-process local reverse-proxy rate-limit sketch:

```nginx
limit_req_zone $binary_remote_addr zone=soland_api:10m rate=600r/m;

server {
  listen 443 ssl;
  server_name soland.example;

  location / {
    limit_req zone=soland_api burst=120 nodelay;
    proxy_pass http://127.0.0.1:8698;
  }
}
```

For multi-replica deployments, enforce the quota at the shared gateway or
load balancer. soland's in-process limiter remains useful as a last-resort
guard, but it is not a distributed budget.

## 8. Local supply-chain artifacts

Generate local image metadata and an SPDX JSON SBOM without pushing an image or
creating a release tag:

```powershell
pwsh ./scripts/local-supply-chain.ps1 -ImageTag soland:local
```

The script writes:

- `target/supply-chain/soland-build-metadata.json` from `docker buildx`
- `target/supply-chain/soland.spdx.json` from `syft`

For local provenance evidence, sign or attest the generated metadata with an
operator-owned key:

```bash
cosign attest-blob \
  --key cosign.key \
  --type slsaprovenance \
  --predicate target/supply-chain/soland-build-metadata.json \
  target/supply-chain/soland-build-metadata.json
```

## 9. Upgrade procedure

1. Read the changelog / release notes for the target tag.
2. `pg_dump` the database.
3. Pull / install the new binary or container image.
4. Restart soland; embedded migrations run on boot.
5. Tail logs for at least one request cycle (`/health`, `/_cokret/describe`).

Downgrades are **not** supported once a migration has run; restore from the
pre-upgrade backup if you need to roll back.

## 10. Hardening checklist

- `SOLAND_DEVELOPMENT_MODE` is unset (or explicitly `false`).
- `SOLAND_OAUTH_INTROSPECTION_URL` points at coauth's `/oauth2/introspect`,
  and `SOLAND_OAUTH_INTROSPECTION_BEARER` matches the shared server-to-server
  secret configured there.
- `DATABASE_URL` uses `sslmode=verify-full` and a password kept out of source
  control (Vault / Kubernetes Secret / systemd `LoadCredential`).
- `SOLAND_CORS_ALLOW_ORIGIN` is the **single** browser origin you trust;
  never `*` while soland sets `Access-Control-Allow-Credentials: true`.
- Object storage uses a dedicated bucket/prefix or a dedicated local volume
  with quota enforcement.
- Reverse proxy enforces TLS 1.2+ and the security headers you require.
- Reverse proxy, API gateway, or load balancer enforces a shared rate-limit
  budget when more than one soland replica is running. soland's built-in
  limiter is per-process and must not be treated as a distributed quota.
- `cargo deny check` runs in CI on every dependabot bump.
- soland process runs as a non-root user (UID 10001 in the local container image).
- Rate-limit configuration matches your anticipated traffic and is enforced
  at the shared gateway when more than one soland replica is running.

## 11. Notary signing-key rotation

The NotaryWorker signs background sub-seals with the seed loaded
from `SOLAND_NOTARY_SIGNING_KEY` (a 32-byte ed25519 seed,
base64-standard-padded). Recommended cadence and ceremony:

- **Rotation cadence**: every **90 days** in steady-state. Same cadence
  on any suspected compromise, with no grace period. Calendar the
  rotation against your secret-rotation tooling (Vault, AWS Secrets
  Manager, ...).
- **Pre-rotation drill**: run
  `cargo run --bin soland-rotate-drill --release` (see
  `src/bin/soland-rotate-drill.rs`) against a staging replica. The
  drill mints a fresh seed, posts it through the live
  `/_soland/admin/notary/rotate-signing-key` path, and verifies the
  hot-swap completed without dropping concurrent signing passes.
- **Production rotation**: stage the new seed in the secret manager,
  call the rotate-signing-key admin endpoint on each replica in turn,
  then retire the old seed. With `SOLAND_USE_KEYSTORE=true` the same
  endpoint also persists the rotated key back into the SDK KeyStore so
  a future restart picks up the new seed automatically.
- **Audit**: every rotation emits a sticky-info tracing event on the
  `notary` target with `rotation_id`, `previous_key_origin`, and the
  new public key's multibase encoding. Capture both the
  pre-rotation and post-rotation public keys in your operations log
  so external verifiers can resolve historical seals.
- **Cross-link**: the runbook (`docs/runbook.md` "Fault-injection
  examples" §4) documents the drill from an on-call perspective.

## 12. Known limits

- **Rate limiting**: the built-in limiter is per-process. Multi-replica
  deployments **MUST** enforce a shared rate-limit budget at the reverse
  proxy or API gateway (see SECURITY.md and `docs/architecture.md` §4).
  Until an external Redis (or equivalent) backend is wired in, treat the
  per-process quota as a single-instance soft floor; production fleets MUST
  front soland with nginx/Caddy/Traefik `limit_req` or an API gateway that
  shares state across replicas.

### CKP-0007 (Circle primitive) — migration & sizing notes

- **Migrations**: the Circle rollout adds three new diesel migrations that
  run automatically on startup —
  `20260526000000_drop_discussion_realm_ref`,
  `20260526010000_add_circles`, and
  `20260526020000_add_scope_circle_id`. The first is a defensive
  `DROP COLUMN IF EXISTS` for vendor forks that persisted the legacy
  cross-Realm discussion routing column; the next two land the
  `projection_circles` / `projection_circle_members` mirror tables and the
  `scope_circle_id` / `default_scope_circle_id` / `child_scope_policy` /
  `effective_scope` columns on the Flow / Morph / Space / Events mirrors.
  All three are forward-only in spirit — the down migrations are provided
  for diesel symmetry but reintroducing `discussion_realm_ref` after the
  CKP-0007 cutover would violate the forbidden-wire-fields contract.
- **Disk sizing**: `effective_scope` adds one nullable `TEXT` column per
  projected Event. For a typical `ck:circle:<uuid>` value the on-wire form
  is 46 bytes; PostgreSQL's `TEXT` overhead pushes the stored cost to ~50
  bytes per row, plus an additional ~20 bytes for the BTREE index entry on
  `projection_events_effective_scope_idx`. A 100M-event projection grows
  by ~7 GiB total (table + index). Drop the index if your deployment never
  filters projection reads by Circle scope.
- **Multi-replica + Circle membership**: the Circle membership FSM lives
  on the durable event log, so cross-replica consistency comes for free
  once the underlying Postgres replication is healthy. The
  `circle_member_must_be_realm_member` invariant is checked in-reducer; a
  replica that hasn't replayed the parent Realm's latest `ck.member.state`
  events will fail-closed on Circle membership writes — the canonical fix
  is to gate writes behind the federation outbox acknowledgement.
- **Metrics**: Prometheus text metrics are exposed on the separate
  `SOLAND_METRICS_BIND` listener (default `127.0.0.1:9090`) at `/metrics`.
- **OpenTelemetry**: OTLP trace export is disabled unless the binary is built
  with `--features otel` and `SOLAND_OTEL_EXPORTER=otlp` is set.
- **Scaffold endpoints**: push outbound bridge, the MIMI provider directory,
  and most of the directory surface return placeholder shapes. See `_todos.md`
  Streams D / E / F for the production rollout.
- **Pre-1.0 schema drift**: protocol field renames listed in `_todos.md` Q2/Q3
  may require client updates between releases.

## R3 migrations

R3 lands new wire surfaces (agent FSM, recovery policy/receipt, media token
exchange, and a re-shaped realm media_service shape). None of the R3
migrations drop columns or tables; everything is additive plus a
read-side normalization for the legacy `sfu_endpoint` shape.

Run order (each migration is idempotent):

1. `migrations/20260520_realm_media_service_foci.sql`
2. `migrations/20260521_recovery_policies.sql`
3. `migrations/20260522_recovery_receipts.sql`
4. `migrations/20260523_agent_fsm_cell_upgrade.sql`

### `ck.realm.media_service.foci[]` shape

The v1.0 realm media-service shape exposed a single endpoint:

```json
{
  "media_service": {
    "sfu_endpoint": "https://sfu.example.org",
    "backend": "livekit"
  }
}
```

R3 normalizes to a `foci[]` array so that a realm can advertise multiple
media foci (e.g. one LiveKit pool and one Mediasoup pool, or
geo-distributed pools):

```json
{
  "media_service": {
    "foci": [
      {
        "focus_id": "ck:focus:livekit:eu-west-1",
        "backend": "livekit",
        "connect_url": "https://sfu.eu-west-1.example.org",
        "issuer_kid": "ck-media-issuer/example/2026-05"
      }
    ]
  }
}
```

Migration `20260520_realm_media_service_foci.sql` does **not** drop the
old column. It:

1. Reads each `realm_media_service.payload` JSONB row.
2. If `foci` already present and non-empty, no-ops.
3. Otherwise, projects the legacy `sfu_endpoint` + `backend` pair into a
   single-entry `foci` array under a derived `focus_id` of
   `ck:focus:legacy:<realm_short>:<sha256(endpoint)[:8]>`.
4. Writes the merged payload back. The legacy keys remain available for
   one full release cycle; reader code accepts either shape and prefers
   `foci[]` when both are present.

Validation post-migration:

```sql
SELECT realm_id,
       payload ? 'foci' AS has_foci,
       jsonb_array_length(payload->'foci') AS focus_count
FROM   realm_media_service
ORDER  BY realm_id
LIMIT  20;
```

Realms with `has_foci = false` after the migration ran indicate either an
empty `media_service` row or a row outside the canonical shape — capture
the row and escalate; do not delete.

### `recovery_policies` + `recovery_receipts`

R3 introduces two new tables. Both are append-only event projections, not
truth tables — the durable record is the canonical event stream; these
projections accelerate reads.

```sql
CREATE TABLE recovery_policies (
    policy_id        UUID PRIMARY KEY,
    principal_id     TEXT NOT NULL,
    policy_version   INTEGER NOT NULL,
    proof_kinds      TEXT[] NOT NULL,
    body             JSONB NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (principal_id, policy_version)
);
CREATE INDEX recovery_policies_principal_idx
    ON recovery_policies(principal_id, policy_version DESC);

CREATE TABLE recovery_receipts (
    receipt_id            UUID PRIMARY KEY,
    recovery_session_id   TEXT NOT NULL,
    principal_id          TEXT NOT NULL,
    proof_summary         JSONB NOT NULL,
    completion_timestamp  TIMESTAMPTZ NOT NULL,
    inserted_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX recovery_receipts_principal_idx
    ON recovery_receipts(principal_id, completion_timestamp DESC);
```

No backfill is required; pre-R3 deployments have zero rows in either
table. The reducer materializes new rows as events arrive.

### Agent FSM cell upgrade

The agent FSM is owned by a cell (`ck.component.agent_state.v1`). Pre-R3
deployments don't carry that cell. Migration
`20260523_agent_fsm_cell_upgrade.sql`:

1. Iterates the existing `agent_principals` projection.
2. For each row, inserts a synthetic `ck.self.agent.provision`-equivalent state
   marker into the cell store with state = `Active` and source =
   `migration:r3`.
3. Sets `lattice = fsm, bottom = reject` on the cell metadata.

Migration is safe to re-run: it uses `ON CONFLICT (agent_principal_id) DO
NOTHING`. Verify:

```sql
SELECT state, COUNT(*) FROM agent_state_cell GROUP BY state;
```

Expected post-migration: every existing agent principal has a row in
`Active`. After the migration, agent operations `pause`, `resume`, and
`deactivate` (POST /agents/{id}/deactivate — the historical `/revoke`
alias is gone) transition the FSM.
