# Deploying soland

Production guidance for running soland as a single-process Arkret v1 reference
server. soland is pre-1.0 — the push outbound bridge, the MIMI provider
directory and most of the directory surface are still scaffold endpoints that
return placeholder shapes. Review them before serving real users.

## Prerequisites

| Component | Recommended | Notes |
| --- | --- | --- |
| OS | Linux (Debian/Ubuntu LTS) | Other targets are CI-tested but less battle-hardened |
| PostgreSQL | 16+ | `pq-src` builds libpq inline; the runtime image only needs the network reachability |
| Reverse proxy | nginx, Caddy, or Traefik | TLS termination is **expected** to live in the reverse proxy, not soland itself |
| Object storage | local volume or S3-compatible bucket | Local disk is fine for one node; production should prefer S3/MinIO/R2-style object storage |
| Key custody | encrypted file + external 32-byte master key | Ciphertext and master key must have separate backup and access-control boundaries |
| Container runtime | Docker / containerd / Podman | Build or load the image locally; this readiness workflow does not push registry images or tags |

## 1. Provision PostgreSQL

```sql
CREATE ROLE soland WITH LOGIN PASSWORD '<strong-random-password>';
CREATE DATABASE soland OWNER soland;
GRANT ALL PRIVILEGES ON DATABASE soland TO soland;
```

soland runs Diesel migrations on startup; no manual DDL is required.

## 2. Configure environment

### Provision the KeyStore master key

Generate the encrypted-file KeyStore master key exactly once, outside the
server startup path. `soland-keystore-keygen` obtains 32 bytes from the
operating-system CSPRNG, writes the Base64 value with create-new semantics,
validates the result, and refuses to overwrite an existing file. The
`--if-missing` option is reserved for idempotent automation such as
`just init-dev`; it still rejects malformed existing files.

Installed-binary usage:

```text
soland-keystore-keygen --output <path>
```

From a source checkout, the command is cross-platform:

```text
cargo run --locked --release -p soland-keystore-keygen -- --output <path>
```

For a Linux Docker host, the release image contains the helper. Create a
host directory writable by the image's UID `10001`, run the helper as an
explicit one-shot operation, and then make the result read-only:

```bash
sudo install -d -m 0700 -o 10001 -g 10001 /secure/soland
docker run --rm \
  --entrypoint /usr/local/bin/soland-keystore-keygen \
  --mount type=bind,source=/secure/soland,target=/secrets \
  ghcr.io/arkret/soland:<tag> \
  --output /secrets/soland-keystore-master-key
sudo chmod 0400 /secure/soland/soland-keystore-master-key
```

On Windows or Windows Docker Desktop, use the same image and protect the host
file with an ACL. Run these commands from PowerShell:

```powershell
$keyDir = 'D:\soland\secrets'
New-Item -ItemType Directory -Force -Path $keyDir | Out-Null
$keyDir = (Resolve-Path -LiteralPath $keyDir).Path

docker run --rm `
  --entrypoint /usr/local/bin/soland-keystore-keygen `
  --mount "type=bind,source=$keyDir,target=/secrets" `
  ghcr.io/arkret/soland:<tag> `
  --output /secrets/soland-keystore-master-key

$keyFile = Join-Path $keyDir 'soland-keystore-master-key'
$account = [Security.Principal.WindowsIdentity]::GetCurrent().Name
icacls $keyFile /inheritance:r /grant:r "${account}:(R)"
```

If Docker runs under a dedicated Windows service account, grant that account
read access instead of the interactive user. Do not place the key in the image,
the source tree, an environment file committed to Git, or the same backup as
`SOLAND_KEYSTORE_PATH`. Preserve the original key for every restart and
restore; losing or replacing it makes the encrypted KeyStore unreadable.

### Configure runtime values

Create a deploy-time `.env` (or a Kubernetes Secret / systemd EnvironmentFile):

```dotenv
SOLAND_BIND=0.0.0.0:8698
SOLAND_PUBLIC_BASE_URL=https://soland.example
SOLAND_TLS_CERT_PATH=/etc/soland/tls/fullchain.pem
SOLAND_TLS_KEY_PATH=/etc/soland/tls/privkey.pem
SOLAND_PQ_TLS_DEPLOYMENT_PROBE=verified
# One-time only on the first production boot; remove after identity creation.
SOLAND_FIRST_PROVISIONING=true
SOLAND_KEYSTORE_BACKEND=encrypted_file
SOLAND_KEYSTORE_PATH=/var/lib/soland/keystore/soland.v1
SOLAND_KEYSTORE_MASTER_KEY_FILE=/run/secrets/soland-keystore-master-key
SOLAND_SERVICE_IDENTITY_BUNDLE_DIR=/var/lib/soland/identity-bundle
SOLAND_EMBEDDED_WEBVH_PROVIDER_ENABLED=true
SOLAND_EMBEDDED_WEBVH_REGISTRATION_BEARER=<shared-secret-configured-in-coauth>
# Optional: use a standalone webvh provider instead of, or alongside, the embedded provider.
# SOLAND_EXTERNAL_WEBVH_PROVIDER_URL=https://webvh.example
# SOLAND_EXTERNAL_WEBVH_REGISTRATION_BEARER=<provider-registration-secret>
# With both values set, Soland's own identity is Provider-backed (class A), so
# SOLAND_FIRST_PROVISIONING is not required.
# SOLAND_DEFAULT_WEBVH_PROVIDER_ID=soland.embedded
SOLAND_ACCOUNT_AUTHORITY_URL=https://coauth.example
SOLAND_ACCOUNT_AUTHORITY_TRUST_DOMAIN=ak:trust_domain:coauth.example
SOLAND_INTERNAL_CHANNEL_INTEGRITY_MODE=registered_tcb
SOLAND_INTERNAL_CHANNEL_DECRYPTING_FORWARDING_PROXIES=soland-edge,coauth-edge
SOLAND_SESSION_GRANT_INTROSPECTION_URL=https://coauth.example/_arkret/gate/account/session-grants/introspect
SOLAND_AUTH_SESSION_LOGOUT_URL=https://coauth.example/_arkret/gate/account/auth-sessions/logout
SOLAND_SESSION_GRANT_INTROSPECTION_BEARER=<shared-secret-configured-in-coauth>
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

### Embedded webvh provider: deployment-profile gate

The embedded webvh provider (`SOLAND_EMBEDDED_WEBVH_PROVIDER_ENABLED=true`)
is only suitable for `ak.profile.personal_node.v1` and
`ak.profile.small_team.v1` deployments. Those profiles accept a single
witness proof with no distinct-controlling-organization requirement, so a
self-hosted provider is a conformant — though explicitly degraded —
identity bootstrap for them.

`ak.profile.organization.v1` and every higher profile MUST NOT bootstrap the
service identity from the embedded (local) provider. The spec witness
baseline (arkret-spec `spec/v1/zh/identity/identity-did.md` §3.4.2) requires
at least 2 valid witness proofs from at least 2 distinct controlling
organizations for those profiles, and forbids host self-witnessing as the
sole basis for high-risk control decisions. soland's local/embedded provider
path performs no witness verification at all (see the trust-root layering
note below), so it can never satisfy that baseline. For `organization` and
above, provision the service identity through an external webvh provider
(`SOLAND_EXTERNAL_WEBVH_PROVIDER_URL` +
`SOLAND_EXTERNAL_WEBVH_REGISTRATION_BEARER`) whose DID log carries the
required independent witness proofs.

### Witness verification is layered by trust root

The describe payload advertises `"webvh_witness_quorum": "unsupported"` only
under the `soland.local_identity_store` trust root
(`crates/http/src/routing/identity/did/webvh.rs`). The flag is scoped, not
global — soland has two distinct did:webvh paths:

- **Local / embedded provider path — always rejects (fail-closed).** DID
  logs handled through the local identity store are validated by
  `webvh_validation::validate_witness_policy_for_log`
  (`crates/http/src/routing/identity/webvh_validation.rs`), which rejects
  any log entry that declares a witness policy with `WitnessQuorumNotMet`.
  No witness proof is ever evaluated on this path. The rejection is
  intentional fail-closed behavior matching the advertised `"unsupported"`;
  it must not be relaxed into unconditional acceptance.
- **External resolution path — real witness verification.**
  Pinned/historical did:webvh resolution
  (`crates/http/src/did_resolver_chain.rs`, `fetch_verified_webvh_history`)
  fetches `did-witness.json` whenever the log declares a witness policy and
  calls the SDK `verify_did_webvh_v1_chain_and_witness_bytes`, performing
  full chain + witness verification. The spec §3.4 requirement that every
  v1 core station MUST support did:webvh witness verification is
  satisfied by this external resolution path, not by the local store.

### Advanced environment reference

Most deployments only need the variables in the sample above. The table below
lists the remaining runtime variables soland reads, including security-sensitive
and rollout-only switches that should be managed deliberately.

| Variable | Default | Purpose |
| --- | --- | --- |
| `SOLAND_ADMIN_PRINCIPAL_IDS` | empty | Comma-separated typed principal ID allowlist (`ak:did_core:…`) for production admin APIs. An empty value closes the admin API outside development mode; browser sessions additionally require `SOLAND_SESSION_GRANT_INTROSPECTION_URL`. |
| `SOLAND_ADMIN_PAGE_LIMIT` | `100` | Default admin API page size. |
| `SOLAND_ADMIN_MAX_PAGE_LIMIT` | `1000` | Maximum admin API page size; clamped above the default. |
| `SOLAND_APPLET_TRANSACTION_INFLIGHT_CAPACITY` | `64` | Maximum concurrent applet transactions retained in memory. |
| `SOLAND_DB_POOL_ACQUIRE_TIMEOUT_SECS` | deadpool default | Positive database-pool acquisition timeout; unset means no explicit wait timeout. |
| `SOLAND_DB_POOL_MAX_SIZE` | CPU count × 4 | Positive database-pool size override. |
| `SOLAND_DID_RESOLVER_ALLOW_METHODS` | `web,key,uuid` | Comma-separated DID methods accepted by outbound DID resolution. |
| `SOLAND_EGRESS_ALLOW_PRIVATE_NETWORKS` | development mode | Authoritative override for private/link-local outbound destinations. Keep `false` in production unless the network path has been explicitly reviewed. |
| `SOLAND_EGRESS_ALLOWED_HOSTS` | empty | Optional comma-separated exact/wildcard outbound host allowlist. |
| `SOLAND_EGRESS_DENYLIST` | empty | Comma-separated outbound host denylist; evaluated in addition to the private-network guard. |
| `SOLAND_EXTERNAL_WEBVH_PROVIDER_TRUST_DOMAIN` | derived trust domain | Expected trust domain for the external webvh provider probe. |
| `SOLAND_FEDERATION_DENYLIST` | empty | Comma-separated federation host/service denylist. |
| `SOLAND_FEDERATION_FANOUT_TOPOLOGY` | `mesh` | Federation fanout topology (`mesh` or `hub`). |
| `SOLAND_FEDERATION_FRONTIER_INTERVAL_SECONDS` | `0` | Optional frontier synchronization interval, at most `3600` seconds; `0` disables periodic polling. |
| `SOLAND_FEDERATION_PEER_DENYLIST` | empty | Additional comma-separated peer denylist. |
| `SOLAND_HEALTHCHECK_URL` | derived from `SOLAND_BIND` | URL used by the built-in healthcheck command. |
| `SOLAND_ICE_STUN_URLS` | `stun:stun.l.google.com:19302` | Comma-separated STUN URLs advertised in signed ICE configs. |
| `SOLAND_ICE_TTL_SECONDS` | `300` | Lifetime of an issued ICE config / TURN credential before refresh; non-positive falls back to default. |
| `SOLAND_ICE_REFRESH_LEAD_SECONDS` | `75` | Lead time before TTL at which clients should refresh the ICE config. |
| `SOLAND_JWS_REPLAY_WINDOW_SECONDS` | `300` | Accepted JWS replay window; `0` disables replay-window enforcement. |
| `SOLAND_KEY_BACKUP_DAILY_DOWNLOAD_LIMIT` | spec default | Per-principal daily key-backup download limit. |
| `SOLAND_NOTARY_SIGNING_KEY` | unset | Base64 (standard or url-safe-no-pad) 32-byte NotaryWorker signing seed. Required outside development mode unless a durable `SOLAND_KEYSTORE_BACKEND` is configured; an ephemeral notary key breaks the Seal signature chain across restarts. |
| `SOLAND_OBJECT_STORAGE_S3_SESSION_TOKEN` | unset | Optional S3 session token for temporary credentials. |
| `SOLAND_OBJECT_STORAGE_S3_SKIP_SIGNATURE` | `false` | Skip S3 request signing for test-only object stores; do not enable for production S3. |
| `SOLAND_RECEIVE_POLICY_*` | unset | Optional ServiceDescribe receive-policy constraints. See `.env.example` for exact names and accepted values. |
| `SOLAND_RATE_LIMIT_TRUST_X_FORWARDED_FOR` | `false` | Trust `X-Forwarded-For` for rate limiting when behind a trusted proxy. |
| `SOLAND_SEED_DEMO_DATA` | `false` | Seed deterministic demo data. Test/development only; never enable in production. |
| `SOLAND_SERVICE_IDENTITY_BUNDLE` | unset | Identity-bundle input used only by `soland-keystore-snapshot`; the server uses `SOLAND_SERVICE_IDENTITY_BUNDLE_DIR`. |
| `SOLAND_SHUTDOWN_GRACE_SECS` | `0` | Graceful-drain bound in seconds; `0` waits indefinitely. |
| `SOLAND_TO_DEVICE_QUEUE_CAPACITY` | `10000` | Per-device in-memory to-device queue capacity. Overflow advances the lost watermark. |
| `SOLAND_TURN_URLS` | `turn:turn.soland.local:3478?transport=udp` | Comma-separated TURN URLs advertised in signed ICE configs. |
| `SOLAND_TURN_SECRET_ROTATION_WINDOW_SECS` | `86400` | Rotation window for the TURN shared secret used in credential derivation. |
| `SOLAND_TURN_SHARED_SECRET` | unset | Optional shared secret folded into derived TURN credentials (`*_FILE` form supported); when unset, credential material is unchanged. |
| `SOLAND_LIVEKIT_API_KEY` | unset | LiveKit API Key. In the LiveKit binding (`bindings/livekit.md` §2) this is the focus `issuer_kid`; the `livekit` focus token issuer fails closed unless the realm focus `issuer_kid` matches this value. |
| `SOLAND_LIVEKIT_API_SECRET` | unset | LiveKit API Secret (`*_FILE` form supported). HMAC-SHA256 signing key for the LiveKit JWT; never exposed in any cell, `/health`, or describe payload. Required together with `SOLAND_LIVEKIT_API_KEY` to mint LiveKit backend tokens. |
| `SOLAND_RESUMABLE_UPLOAD_DIR` | `./soland-resumable-uploads` | Directory for resumable-upload staging files. |
| `SOLAND_RESUMABLE_UPLOAD_TTL_SECS` | `86400` | Incomplete resumable-upload TTL; minimum 60 seconds. |
| `SOLAND_SOVEREIGN_ENCLAVE` | `false` | Enables the sovereign-enclave startup and egress security posture; it does not advertise a conformance profile. |
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
Description=soland — Arkret v1 Station
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
  -e SOLAND_FIRST_PROVISIONING=true \
  -e SOLAND_KEYSTORE_BACKEND=encrypted_file \
  -e SOLAND_KEYSTORE_PATH=/var/lib/soland/keystore/soland.v1 \
  -e SOLAND_KEYSTORE_MASTER_KEY_FILE=/run/secrets/soland-keystore-master-key \
  -e SOLAND_SERVICE_IDENTITY_BUNDLE_DIR=/var/lib/soland/identity-bundle \
  -e SOLAND_ACCOUNT_AUTHORITY_URL=https://coauth.example \
  -e SOLAND_ACCOUNT_AUTHORITY_TRUST_DOMAIN=ak:trust_domain:coauth.example \
  -e SOLAND_INTERNAL_CHANNEL_INTEGRITY_MODE=registered_tcb \
  -e SOLAND_INTERNAL_CHANNEL_DECRYPTING_FORWARDING_PROXIES=soland-edge,coauth-edge \
  -e SOLAND_SESSION_GRANT_INTROSPECTION_URL=https://coauth.example/_arkret/gate/account/session-grants/introspect \
  -e SOLAND_AUTH_SESSION_LOGOUT_URL=https://coauth.example/_arkret/gate/account/auth-sessions/logout \
  -e SOLAND_SESSION_GRANT_INTROSPECTION_BEARER=<shared-secret-configured-in-coauth> \
  -e DATABASE_URL=postgres://soland:<password>@db:5432/soland?sslmode=verify-full \
  -e SOLAND_OBJECT_STORAGE_BACKEND=filesystem \
  -e SOLAND_OBJECT_STORAGE_LOCAL_ROOT=/var/lib/soland/objects \
  -e RUST_LOG=soland=info \
  --mount type=volume,source=soland-data,target=/var/lib/soland \
  --mount type=bind,source=/secure/soland/soland-keystore-master-key,target=/run/secrets/soland-keystore-master-key,readonly \
  ghcr.io/arkret/soland:<tag>
```

The image runs as UID `10001`. Mounted volumes for
`SOLAND_OBJECT_STORAGE_LOCAL_ROOT` must be chowned to that UID (or use a named
Docker volume so Docker handles it). The mounted KeyStore master-key file must
be readable by UID `10001`; generate and back it up separately from the named
ciphertext volume. After the first successful identity creation, recreate the
container without `SOLAND_FIRST_PROVISIONING`; it is a one-time authorization,
not a permanent runtime setting. S3-compatible backends do not need a media
volume.

### Helm

The production chart lives at `deploy/helm/soland`. Render it before applying
so secrets and network ranges are explicit in the release artifact:

```bash
helm template soland ./deploy/helm/soland \
  --namespace arkret \
  --set image.tag=<tag> \
  --set existingSecret=soland-runtime \
  --set env.SOLAND_PUBLIC_BASE_URL=https://soland.example \
  --set env.SOLAND_FIRST_PROVISIONING=true \
  --set env.SOLAND_KEYSTORE_BACKEND=encrypted_file \
  --set env.SOLAND_KEYSTORE_PATH=/var/lib/soland/keystore/soland.v1 \
  --set env.SOLAND_ACCOUNT_AUTHORITY_URL=https://coauth.example
```

Create `soland-runtime` through the cluster's secret-management path before
rendering or installing the chart. It must provide every key listed under
`secretEnv` in `values.yaml`, including `SOLAND_KEYSTORE_MASTER_KEY`. Prefer an
external secret controller or encrypted GitOps secret; do not pass secret
values through Helm `--set`, where they can leak into shell history and release
metadata.

Install the same values with:

```bash
helm upgrade --install soland ./deploy/helm/soland \
  --namespace arkret --create-namespace \
  -f production-values.yaml
```

For production, set `networkPolicy.enabled=true` and provide
`networkPolicy.egress.databaseCidrs`, `objectStorageCidrs`, and `oauthCidrs`
for the actual PostgreSQL, S3-compatible object storage, and coauth
introspection endpoints. Leave `SOLAND_DEVELOPMENT_MODE` unset; the chart
does not set it by default.

## 4. Front with TLS

soland speaks plaintext HTTP — terminate TLS in the reverse proxy.
The Arkret v1 transport baseline requires TLS 1.3 connections to negotiate
`X25519MLKEM768` and fail closed when the peer cannot offer it. Run that
handshake probe against the externally reachable client-service and
service-to-service listener, then set `SOLAND_PQ_TLS_DEPLOYMENT_PROBE=verified`
only for a passing deployment. Production `/readyz` returns 503 until that
machine-verifiable probe evidence is present.

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

Make sure the proxy passes the `Authorization`, `X-Arkret-Wait-For`,
`X-Arkret-SHA256`, and `Range` request headers; soland sends back
`Retry-After`, `X-Arkret-Wait-For-Satisfied`, `Content-Range`, and
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
| Service identity database rows + identity bundle | Stable DID, WebVH history, and public recovery evidence | Back up the database and `SOLAND_SERVICE_IDENTITY_BUNDLE_DIR`; keep private keys in the configured secret store |
| Encrypted KeyStore | Service signing and WebVH control seeds | Back up `SOLAND_KEYSTORE_PATH` and its master key through separate systems; neither artifact is recoverable from the other |

Restore order: stop soland → restore DB, identity bundle, and encrypted KeyStore → restore the master key through its secret-management path → restore object storage bucket/volume → start soland.
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
- `soland_federation_outbox_depth` (rows still owed to a peer: `pending` +
  `leased`)
- `soland_federation_outbox_state_depth{state,peer}` — per-peer breakdown
  across the full lifecycle, including `policy_suppressed`
- `soland_federation_outbox_oldest_pending_age_seconds`
- `soland_federation_retry_delay_seconds` histogram
- `soland_federation_outbox_lease_takeover_total`
- `soland_federation_outbox_dead_letter_total{reason}` (P5 — counter; alert on
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
5. Tail logs for at least one request cycle (`/health`, `/_arkret/describe`).

Downgrades are **not** supported once a migration has run; restore from the
pre-upgrade backup if you need to roll back.

## 10. Hardening checklist

- `SOLAND_DEVELOPMENT_MODE` is unset (or explicitly `false`).
- `SOLAND_ACCOUNT_AUTHORITY_URL` points at coauth's public account authority,
  and `SOLAND_ACCOUNT_AUTHORITY_TRUST_DOMAIN` is its explicit source trust
  domain. It is never inferred from the URL.
- The Account Authority signs as this Station with a delegated assertion method, even when it runs at a separate origin.
- `SOLAND_SESSION_GRANT_INTROSPECTION_URL` points at coauth's
  `/_arkret/gate/account/session-grants/introspect`, and
  `SOLAND_SESSION_GRANT_INTROSPECTION_BEARER` matches the shared
  server-to-server secret configured there (coauth's
  `stations[].session_grant_introspection_bearer` for this Station).
- Before registering the channel, Soland canonicalizes
  `SOLAND_ACCOUNT_AUTHORITY_URL` and requires every configured bearer target to
  use its exact origin (same scheme, host and effective port). Introspection and
  Auth-side logout must use their exact operation paths; credentials, query and
  fragment are forbidden. The controller-gate target is derived as its exact
  path on that same origin. Any conflict aborts startup before the bearer can be
  sent.
- Setting that bearer together with the Authority URL/trust domain and a valid
  `SOLAND_INTERNAL_CHANNEL_INTEGRITY_MODE` registers the
  `service-http-binding.md` §2.2.3 deployment-internal authenticated channel
  between this Station and that Account Authority. The channel carries exactly
  four registered operations: exact-token introspection, Auth-side logout and
  controller-gate attestation issue outbound, plus
  `ak.peer.device_revocations.command.check.v1` inbound. Nothing else on
  `/_arkret/peer/*` accepts it; every other peer operation keeps its RFC 9421
  service signature.
  `mtls_direct_process` means mTLS terminates directly in both business
  processes; ordinary TLS termination at a proxy does not qualify.
  `registered_tcb` requires
  `SOLAND_INTERNAL_CHANNEL_DECRYPTING_FORWARDING_PROXIES` to list every
  decrypting/forwarding proxy in the same TCB, with non-empty unique entries.
  "Every hop is TLS" does not satisfy it. Missing, invalid or incomplete
  integrity configuration leaves the unsigned channel unregistered and its
  operations fail closed.
- `SOLAND_AUTH_SESSION_LOGOUT_URL` independently points at coauth's exact
  `/_arkret/gate/account/auth-sessions/logout` S2S operation; it is never
  inferred from the introspection URL.
- `DATABASE_URL` uses `sslmode=verify-full` and a password kept out of source
  control (Vault / Kubernetes Secret / systemd `LoadCredential`).
- `SOLAND_CORS_ALLOW_ORIGIN` is the **single** browser origin you trust;
  never `*` while soland sets `Access-Control-Allow-Credentials: true`.
- Object storage uses a dedicated bucket/prefix or a dedicated local volume
  with quota enforcement.
- Reverse proxy enforces TLS 1.2+ and the security headers you require.
- Reverse proxy / gateway TLS 1.3 probe verifies `X25519MLKEM768` negotiation
  and sets `SOLAND_PQ_TLS_DEPLOYMENT_PROBE=verified`; classical fallback is not
  accepted.
- Reverse proxy, API gateway, or load balancer enforces a shared rate-limit
  budget when more than one soland replica is running. soland's built-in
  limiter is per-process and must not be treated as a distributed quota.
- `cargo deny check` runs in CI on every dependabot bump.
- soland process runs as a non-root user (UID 10001 in the local container image).
- Rate-limit configuration matches your anticipated traffic and is enforced
  at the shared gateway when more than one soland replica is running.

## 11. Service-identity signing-key custody

The active signing key is bound to the WebVH DID document and persisted
service-identity bundle. Soland does not expose an online key-only rotation
endpoint: changing only the runtime or KeyStore seed would split those
authorities. A future rotation workflow must commit the KeyStore write,
WebVH update, DID document, identity bundle and recovery material as one
recoverable transition before an admin route is added.

Use `soland-keystore-snapshot --export-only` and `--import-only` only for
backup/restore of the already-bound key. They do not rotate identity material.

## 12. Known limits

- **Rate limiting**: the built-in limiter is per-process. Multi-replica
  deployments **MUST** enforce a shared rate-limit budget at the reverse
  proxy or API gateway (see SECURITY.md and `docs/architecture.md` §4).
  Until an external Redis (or equivalent) backend is wired in, treat the
  per-process quota as a single-instance soft floor; production fleets MUST
  front soland with nginx/Caddy/Traefik `limit_req` or an API gateway that
  shares state across replicas.

### AKP-0007 (Circle primitive) — migration & sizing notes

- **Schema**: the `projection_circles` / `projection_circle_members` mirror
  tables and the `scope_circle_id` / `default_scope_circle_id` /
  `child_scope_policy` / `effective_scope` columns on the Strand / Morph /
  Space / Events mirrors are part of the squashed
  `00000000000000_initial` migration; there is no separate Circle upgrade
  step.
- **Disk sizing**: `effective_scope` adds one nullable `TEXT` column per
  projected Event. A complete `ak:circle:<44-char event token>` value is 54
  bytes on the wire; PostgreSQL's short `TEXT` header and tuple alignment put
  the stored cost around 55–60 bytes per row, plus the BTREE index entry on
  `projection_events_effective_scope_idx`. A 100M-event projection grows
  by ~7 GiB total (table + index). Drop the index if your deployment never
  filters projection reads by Circle scope.
- **Multi-replica + Circle membership**: the Circle membership FSM lives
  on the durable event log, so cross-replica consistency comes for free
  once the underlying Postgres replication is healthy. The
  `circle_member_must_be_realm_member` invariant is checked in-reducer; a
  replica that hasn't replayed the parent Realm's latest `ak.member.state`
  events will fail-closed on Circle membership writes — the canonical fix
  is to gate writes behind the federation outbox acknowledgement.
- **Metrics**: Prometheus text metrics are exposed on the separate
  `SOLAND_METRICS_BIND` listener (default `127.0.0.1:9090`) at `/metrics`.
- **OpenTelemetry**: OTLP trace export is disabled unless the binary is built
  with `--features otel` and `SOLAND_OTEL_EXPORTER=otlp` is set.
- **Scaffold endpoints**: push outbound bridge, the MIMI provider directory,
  and most of the directory surface return placeholder shapes.
- **Pre-1.0 schema drift**: protocol field renames may require client updates
  between releases.

## Pre-1.0 schema initialization

Soland keeps the current pre-1.0 schema in
`crates/storage-postgres/migrations/00000000000000_initial`. New deployments
run that migration as a unit; the historical per-feature R3 migration list is
no longer part of this repository.

### `ak.realm.media_service.foci[]` shape

R3 uses a `foci[]` array so that a realm can advertise multiple
media foci (e.g. one LiveKit pool and one Mediasoup pool, or
geo-distributed pools):

```json
{
  "media_service": {
    "foci": [
      {
        "focus_id": "livekit_eu-west-1",
        "backend": "livekit",
        "connect_url": "https://sfu.eu-west-1.example.org",
        "issuer_kid": "ak.media-issuer/example/2026-05"
      }
    ]
  }
}
```

A `media_service` cell without a non-empty `foci[]` array is outside the
canonical shape — capture the row and escalate; do not delete.

### ICE / TURN vs. media-service foci — two distinct config layers

Media connectivity is configured in two independent layers:

- **Per-deployment ICE/STUN/TURN (P2P NAT traversal)** — set via the
  `SOLAND_ICE_*` / `SOLAND_TURN_*` env vars above. These feed the signed
  `POST /_arkret/self/rtc/ice-config` response. Defaults reproduce the
  historical hardcoded `stun.l.google.com` / `turn.soland.local` values so
  existing deployments behave identically until overridden. Point
  `SOLAND_TURN_URLS` at your own coturn/eturnal pool for production.
- **Per-realm SFU foci (LiveKit / Mediasoup conferencing)** — declared in the
  realm `ak.component.realm.media_service.v1` cell as the `foci[]` array shown
  above, consumed by the AKP-0010 token exchange at
  `POST /_arkret/self/rtc/token`. This is where a LiveKit pool's
  `connect_url` / `issuer_kid` / `audience` are bound; it is realm-scoped
  config, not a deployment env var.
  - **LiveKit API Key/Secret** are the one piece of the LiveKit binding that
    *is* a deployment env var: set `SOLAND_LIVEKIT_API_KEY` +
    `SOLAND_LIVEKIT_API_SECRET` so the `livekit` focus mints a standard
    LiveKit JWT (`HS256` over `header.payload`, signed with the API Secret —
    `bindings/livekit.md` §2). The realm focus `issuer_kid` MUST equal
    `SOLAND_LIVEKIT_API_KEY`; a mismatch (or unset credentials) fails the
    token exchange closed instead of issuing a token LiveKit would reject.
    v1 supports a single API Key/Secret pair; mapping multiple LiveKit
    deployments (one pair per cluster, keyed by focus `issuer_kid`) is
    follow-up work.

### Recovery persistence

The initial schema contains `recovery_policies`, `recovery_sessions`,
`security_transactions`, their step outcomes/attempts, and durable terminal
artifacts. There is deliberately no standalone `recovery_receipts` table or
write path: a terminal recovery receipt is accepted only as the signed final
artifact of its `RecoveryTransaction`, and exact replay is served from that
transaction's durable first outcome.

### Agent FSM cell

The agent FSM is owned by a cell (`ak.component.agent_state.v1`) with
`lattice = fsm, bottom = reject`. Agent operations `pause`, `resume` and
`deactivate` (`POST /agents/{id}/deactivate`) transition it.
