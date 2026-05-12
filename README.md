# soland

Reference Contrix v1 principal server, built with Salvo, Diesel, and
PostgreSQL. The HTTP surface mirrors `contrix-spec/spec/v1/artifacts/openapi/contrix-service-api.openapi.yaml`;
in-memory mode keeps the same API for fast local iteration.

> See [DEPLOYMENT.md](DEPLOYMENT.md) for production guidance, [SECURITY.md](SECURITY.md)
> for vulnerability disclosure, and [../_todos.md](../_todos.md) for the open
> task list.

## Quick start

soland depends on the `contrix` crate at `../contrix-rust-sdk/crates/sdk`.
Clone both repos side by side:

```bash
git clone https://github.com/contrix/contrix-rust-sdk.git
git clone https://github.com/contrix/soland.git
cd soland
```

The shortest local workflow uses [`just`](https://github.com/casey/just).
Install it if needed:

```bash
cargo install just
```

Run `just` to see every available recipe.

### Run with the in-memory store (no database)

```bash
just start
```

`DATABASE_URL` is optional. Without it, soland runs with an in-memory repository
and demo Space data while keeping the same HTTP API. `SOLAND_DEVELOPMENT_MODE`
**defaults to `false`**; turn it on explicitly when you need `dev_login`,
the admin snapshot endpoints, or the relaxed DID-document validation that
the development workflow relies on. The `just start` recipe sets it to `true`
for local runs unless you override it.

### Run against PostgreSQL

```bash
just start-db
```

`just start-db` starts a local `postgres:16` container named `soland-postgres`,
waits for it to accept connections, then starts soland with the connection
string below. This path requires Docker:

```dotenv
DATABASE_URL=postgres://soland:soland@localhost:5432/soland
```

Embedded Diesel migrations run on every startup; the tables are created
idempotently. To stop the local database container:

```bash
just db-down
```

If you prefer a persistent `.env`, copy the example and uncomment or replace
the `DATABASE_URL` line:

```bash
just init-env
```

Then `just start` will use the database configured in `.env`.

Manual equivalent:

```bash
DATABASE_URL=postgres://soland:soland@localhost:5432/soland \
  SOLAND_DEVELOPMENT_MODE=true \
  cargo run -- --bind 127.0.0.1:8698
```

### Run with Docker

```bash
docker run --rm -p 8698:8698 \
  -e SOLAND_PUBLIC_BASE_URL=https://soland.example \
  -e SOLAND_SERVICE_DID=did:web:soland.example \
  -e DATABASE_URL=postgres://soland:soland@db:5432/soland \
  -e SOLAND_OBJECT_STORAGE_BACKEND=local \
  -e SOLAND_OBJECT_STORAGE_LOCAL_ROOT=/var/lib/soland/objects \
  -v soland-objects:/var/lib/soland \
  ghcr.io/contrix/soland:latest
```

See [DEPLOYMENT.md](DEPLOYMENT.md) for a full Docker / PostgreSQL / TLS guide.

## Configuration

All settings can be supplied via environment variables (preferred) or a
`.env` file at the working directory.

| Variable | Default | Purpose |
| --- | --- | --- |
| `SOLAND_BIND` (or `--bind`) | `127.0.0.1:8698` | Listen address |
| `SOLAND_PUBLIC_BASE_URL` | `http://<bind>` | Advertised base URL (`/api/v1/server/describe`) |
| `SOLAND_SERVICE_DID` | `did:web:soland.local` | Service DID — also the proof `audience` binding |
| `DATABASE_URL` | unset | If set, enables PostgreSQL and runs migrations |
| `SOLAND_OBJECT_STORAGE_BACKEND` | `local` | Blob object backend: `local` or `s3-compatible` |
| `SOLAND_OBJECT_STORAGE_LOCAL_ROOT` | system temp + `/soland-objects` | Local filesystem root when using `local` |
| `SOLAND_OBJECT_STORAGE_PREFIX` | unset | Optional object key prefix shared by local and S3-compatible backends |
| `SOLAND_OBJECT_STORAGE_S3_BUCKET` | required for S3 | S3-compatible bucket name |
| `SOLAND_OBJECT_STORAGE_S3_ENDPOINT` | region endpoint | Optional custom endpoint for MinIO/R2/etc. |
| `SOLAND_CORS_ALLOW_ORIGIN` | unset | Single explicit CORS origin for browser clients |
| `SOLAND_DEVELOPMENT_MODE` | `false` | Enable dev-only endpoints (`dev_login`, admin snapshots, relaxed DID validation) |
| `RUST_LOG` | unset | Tracing subscriber filter, e.g. `soland=info,salvo=warn` |

When `SOLAND_DEVELOPMENT_MODE=false` (the default), submitted commits must use
production proof material — no `alg: none` or `dev-proof`, proof `payload_hash`
must match the canonical commit digest, the verification method must be rooted
in the commit author DID, and proof `domain`/`audience` must bind to
`SOLAND_SERVICE_DID`.

Client-sync `next_batch` cursors are structured `cx:cursor:` tokens bound to
the principal, device, service DID, filter hash, stream positions, and expiry.
Passing `since` returns incremental timeline events; expired cursors fail with
`sync_token_expired`.

Development bearer sessions are stored server-side by service-bound SHA-256
token hash, not plaintext token. Logout records `revoked_at` and revoked
sessions are rejected on later requests. To-device messages remain deliverable
across duplicate syncs until the client presents a cursor with the acknowledged
to-device position. Blob downloads require a bearer session plus a `purpose`
query parameter; blobs are visible to the uploader or to members of the bound
Space.

The v1 primary write path is the signed Event Envelope API: `GET /api/v1/events/describe`
declares the active event registry, schema/reducer profiles, and limits, and
`POST /api/v1/events` accepts one canonical Event Envelope.

Federation transaction IDs are recorded per origin with canonical request
digests. Replaying the same `(origin, txn_id)` and body returns the stored
response; reusing the transaction ID with different content returns a
conflict. PostgreSQL mode persists these replay records. Blob uploads
normalize MIME types and filenames, enforce per-upload/account/Space quotas,
and reject plaintext blobs in private Spaces unless this service is listed in
`plaintext_visible_services`.

## API surface

soland exposes the canonical Contrix v1 routes (~180 routes total). Highlights:

- `GET  /health` — liveness + DB/repo health (used as the Docker healthcheck)
- `GET  /.well-known/contrix/openapi.json` and `.../openapi.yaml` — the
  generated OpenAPI 3.1 document seeded with `contrix_sdk::salvo_adapter::register_contrix_oapi_components`
- `GET  /.well-known/mimi-protocol-directory`
- `POST /api/v1/events`, `GET /api/v1/events/describe`, …
- `GET /api/v1/sync`, `GET /api/v1/identity/*`, `GET /api/v1/directory/*`
- `POST /api/v1/auth/dev-login` (development_mode only)

A complete list lives in the OpenAPI document above; `/api/v1/admin/{resource}`
and `/api/v1/auth/dev-login` are gated behind `SOLAND_DEVELOPMENT_MODE=true`.

## Development

Workspace layout (the CI checkout assumes the same):

```
contrix-dev/
├── contrix-rust-sdk/       # https://github.com/contrix/contrix-rust-sdk
│   └── crates/sdk
└── soland/                 # this repo
    ├── src/
    ├── tests/
    └── Cargo.toml
```

```bash
just fmt-check     # respects rustfmt.toml
just check
just test
```

The OpenAPI snapshot test (`contrix_openapi_spec_contains_facet_projection_contracts`
in `tests/http_api.rs`) locks the operation-id surface at the framework level;
`tests/http_api.rs` covers protocol behaviors. See the root `../_todos.md` `F5/F6`
entries for the known pre-existing test failures.

## Status & roadmap

The current implementation has product-shaped auth/session, identity, repo
adapter, device key, to-device, blob, directory, sync, and index surfaces.
PostgreSQL migrations and the repo adapter are wired; in-memory mode is the
development fallback. Remaining production work is tracked in
[`../_todos.md`](../_todos.md) — reducer-backed projections, full policy ordering,
durable projection/device sub-stores, full E2EE client workflow, anti-enumeration, and
the complete federation/media/recovery/key-backup surfaces.

## License

Apache-2.0 — see [LICENSE](LICENSE).
