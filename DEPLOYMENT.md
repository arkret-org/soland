# Deploying soland

Production guidance for running soland as a single-process Contrix v1 reference
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
| Container runtime | Docker / containerd / Podman | Image is published to `ghcr.io/contrix/soland` on every tagged release |

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

Validate the env block on the target host once:

```bash
soland --bind "${SOLAND_BIND}" --help    # cheap startup sanity check
```

## 3. Run the binary

### systemd unit

```ini
[Unit]
Description=soland — Contrix v1 principal server
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
  ghcr.io/contrix/soland:<tag>
```

The image runs as UID `10001`. Mounted volumes for
`SOLAND_OBJECT_STORAGE_LOCAL_ROOT` must be chowned to that UID (or use a named
Docker volume so Docker handles it). S3-compatible backends do not need a media
volume.

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

Make sure the proxy passes the `Authorization`, `X-Contrix-Wait-For`,
`X-Contrix-SHA256`, and `Range` request headers; soland sends back
`Retry-After`, `X-Contrix-Wait-For-Satisfied`, `Content-Range`, and
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

Today soland emits structured `tracing` events at `info` and above. Future
roadmap (see `_todos.md` Q5 / Dep-6):

- per-handler `instrument` spans carrying `actor / space / event_kind`
- `/metrics` Prometheus surface
- OpenTelemetry exporter

Until then, ship `RUST_LOG=soland=info` to your log pipeline and alert on:

- `200 /health` request rate dropping below the configured threshold
- 5xx error rate over rolling 5-minute windows
- `auth.dev_login` audit events outside the development environment (this
  should be impossible with `SOLAND_DEVELOPMENT_MODE=false`, but alert
  belt-and-braces)

## 8. Upgrade procedure

1. Read the changelog / release notes for the target tag.
2. `pg_dump` the database.
3. Pull / install the new binary or container image.
4. Restart soland; embedded migrations run on boot.
5. Tail logs for at least one request cycle (`/health`, `/api/v1/server/describe`).

Downgrades are **not** supported once a migration has run; restore from the
pre-upgrade backup if you need to roll back.

## 9. Hardening checklist

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
- `cargo deny check` runs in CI on every dependabot bump.
- soland process runs as a non-root user (UID 10001 in the published image).
- Rate-limit configuration matches your anticipated traffic
  (`_todos.md` Q6 / Cfg-1 — currently single-process).

## 10. Known limits

- **Single-process**: soland is a reference implementation. Multi-replica
  deployments need an out-of-process rate-limit store (`_todos.md` Q6) and
  durable persistence for everything in `_todos.md` F2.
- **Scaffold endpoints**: push outbound bridge, the MIMI provider directory,
  and most of the directory surface return placeholder shapes. See `_todos.md`
  Streams D / E / F for the production rollout.
- **No metrics endpoint yet** (`_todos.md` Dep-6).
- **Pre-1.0 schema drift**: protocol field renames listed in `_todos.md` Q2/Q3
  may require client updates between releases.
