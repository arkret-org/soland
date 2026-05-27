# soland

Reference Contrix v1 principal server, built with Salvo, Diesel, and
PostgreSQL. The HTTP surface mirrors `contrix-spec/spec/v1/artifacts/openapi/contrix-service-api.openapi.yaml`;
in-memory mode keeps the same API for fast local iteration.

> See [DEPLOYMENT.md](DEPLOYMENT.md) for production guidance, [SECURITY.md](SECURITY.md)
> for vulnerability disclosure, and [../_todos.md](../_todos.md) for the open
> task list. Operator-facing internals:
>
> - [`docs/architecture.md`](docs/architecture.md) — reducer / projection
>   pipeline, federation outbox, MLS lifecycle, multi-replica notes.
> - [`docs/runbook.md`](docs/runbook.md) — common error codes, log-search
>   recipes, restart strategy, fault-injection drills.
> - [`docs/federation-s2s.md`](docs/federation-s2s.md) — peer onboarding,
>   the three signed `Source-Trust-Domain` / `Destination-Trust-Domain` /
>   `Request-Canonical-Digest` headers, trust-domain immutability.
> - [`examples/prometheus-alerts.yml`](examples/prometheus-alerts.yml) —
>   ready-made alert rules (audit-append failures, federation DLQ rate,
>   /readyz outages).

## Realm vs Space

Following the Phase 1–4 terminology inversion (Round R1.x — wire-breaking):

- **Realm:** security boundary — membership, capability, E2EE, federation.
  Reducer cells live under `cx.realm.*`; admin routes use `/realms/:id/...`.
  Old name on the wire: `Space`.
- **Space:** navigation container — board, list, section, calendar bucket
  inside a Realm. Old name on the wire: `Place`.

`cx.realm.link`, `cx.realm.inheritance_policy`, and `cx.capability.derived`
are the new typed edges that wire boundaries together (governed_by /
discoverable_from / mirror_of). Legacy `space_*` and `place_*` payload
fields remain accepted as serde aliases.

## Round R4 (protocol review closures)

Spec round 4 (`contrix-spec` range `2a4d39b..a77b995`, 8 commits) lands
on top of R2/R3. See [`CHANGELOG.md`](CHANGELOG.md) `[Unreleased]` and
[`../_todos.md`](../_todos.md) for the canonical wire-breaking list.
Operator-visible highlights:

- **`trust_domain` is now immutable on a Realm** — captured by
  `cx.realm.create` and locked thereafter. Cross-domain replays reject
  with `cross_domain_replay_rejected`.
- **`ServiceDescribe` v2** — `cx.server.describe` / `cx.account.describe` /
  `cx.events.describe` / `cx.applet.describe` return the 17-field
  canonical envelope, including `trust_domain` / `plaintext_visibility` /
  `verified_profiles` / `development_mode` and a `rate_limit` oneOf.
- **`/events/frontier` split by role** — `peer_role` query param routes
  to `account_client` / `federation_peer` / `anonymous_health`. The
  anonymous shape strips `receipts` and `actor_seq_upper_bounds`.
- **`/events/subscribe` typed frames** — NDJSON now emits typed
  `EventsSubscribeFrame{event|frontier|heartbeat|catchup_complete|
  epoch_rotation|dropped|resync_required|unauthorized}`. `dropped`
  MUST carry `cursor`.
- **Federation S2S transport adds three signed headers** —
  `Source-Trust-Domain`, `Destination-Trust-Domain`,
  `Request-Canonical-Digest`. Verified into the signature transcript;
  mismatch rejects.
- **Federation idempotency `historical_only`** — cache hits after
  source-key revocation return the cached body with
  `reason_code=historical_only`; no side effects.
- **Delivery-binding handover error codes** —
  `delivery_binding_stale` (with `new_recipient_service_did` +
  `handover_frontier`) and `delivery_binding_handed_over`.
- **`cx.cross_signing.publish` CAS** —
  `expected_previous_generation == current && new = current + 1`,
  verified before signature.

## Round R2/R3 deployment requirements

Spec rounds 2+3 (2026-05-20) introduced wire-breaking changes that the
operator must address at boot — see
[`CHANGELOG.md`](CHANGELOG.md) `[Unreleased]` and
[`../contrix-spec/CHANGELOG.md`](../contrix-spec/CHANGELOG.md) for the
normative source. The key operational hooks:

- **`SOLAND_TRUST_DOMAIN`** — required `cx:trust_domain:<scope>` value
  (defaults to a value derived from the configured `service_did`).
  Enters the canonical transcript of every `cx.cross_signing.reset`
  proof; rotating this value invalidates outstanding proofs.
- **Ephemeral kinds rejected on `POST /api/v1/events`** — producers
  must route the 12 ephemeral kinds (`cx.call.signal`, `cx.presence`,
  `cx.typing`, `cx.receipt.read`, `cx.key.verification.*`) through
  the ephemeral envelope / device-message channels; no compatibility
  shim.
- **Realm terminal-state, presign blob fail-closed, federation
  idempotency cache, relaxed window ≤ 300 s** — see CHANGELOG for
  the full operator checklist.

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

`DATABASE_URL` is optional. Without it, soland runs with an in-memory store
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
  -e SOLAND_OAUTH_INTROSPECTION_URL=https://coauth.example/oauth2/introspect \
  -e SOLAND_OAUTH_INTROSPECTION_BEARER=shared-secret-known-by-coauth \
  -e DATABASE_URL=postgres://soland:soland@db:5432/soland \
  -e SOLAND_OBJECT_STORAGE_BACKEND=filesystem \
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
| `SOLAND_TLS_CERT_PATH` | unset | TLS certificate PEM path; when paired with `SOLAND_TLS_KEY_PATH`, soland serves HTTPS via rustls |
| `SOLAND_TLS_KEY_PATH` | unset | TLS private-key PEM path paired with `SOLAND_TLS_CERT_PATH` |
| `SOLAND_SERVICE_DID` | `did:web:soland.local` | Service DID — also the proof `audience` binding |
| `SOLAND_EMBEDDED_WEBVH_PROVIDER_ENABLED` | `true` | Enable soland's built-in `did:webvh` provider for coauth registration |
| `SOLAND_EMBEDDED_WEBVH_REGISTRATION_BEARER` | unset | Shared bearer token coauth must present to write embedded `did:webvh` registrations |
| `SOLAND_EXTERNAL_WEBVH_PROVIDER_URL` | unset | Optional external `did:webvh` provider, such as a standalone StarID service |
| `SOLAND_DEFAULT_WEBVH_PROVIDER_ID` | unset | Optional coauth default provider id: `soland.embedded` or `external.webvh` |
| `SOLAND_OAUTH_INTROSPECTION_URL` | unset | coauth OAuth introspection endpoint for direct bearer-token auth |
| `SOLAND_OAUTH_INTROSPECTION_BEARER` | unset | Server-to-server bearer sent to the introspection endpoint |
| `DATABASE_URL` | unset | If set, enables PostgreSQL and runs migrations |
| `SOLAND_OBJECT_STORAGE_BACKEND` | `filesystem` | Blob object backend: `filesystem`/`local` or `s3-compatible` |
| `SOLAND_OBJECT_STORAGE_LOCAL_ROOT` | system temp + `/soland-objects` | Local filesystem root when using `filesystem`/`local` |
| `SOLAND_OBJECT_STORAGE_PREFIX` | unset | Optional object key prefix shared by local and S3-compatible backends |
| `SOLAND_OBJECT_STORAGE_S3_BUCKET` | required for S3 | S3-compatible bucket name |
| `SOLAND_OBJECT_STORAGE_S3_ENDPOINT` | region endpoint | Optional custom endpoint for MinIO/R2/etc. |
| `SOLAND_CORS_ALLOW_ORIGIN` | unset | Single explicit CORS origin for browser clients |
| `SOLAND_AUTH_SERVER_URL` | unset | Public Auth / Account Server URL advertised to browser clients; registration and recovery calls go there |
| `SOLAND_DEVELOPMENT_MODE` | `false` | Enable dev-only endpoints (`dev_login`, admin snapshots, relaxed DID validation) |
| `SOLAND_MAX_REQUEST_SIZE` | `1048576` | Maximum request body bytes Salvo will read before returning `413 Payload Too Large` |
| `SOLAND_METRICS_BIND` | `127.0.0.1:9090` | Separate Prometheus listener; scrape `/metrics` |
| `SOLAND_OTEL_EXPORTER` | unset | Set to `otlp` when built with `--features otel` to export traces |
| `SOLAND_OTEL_ENDPOINT` | `http://127.0.0.1:4317` | OTLP gRPC collector endpoint when OTEL export is enabled |
| `SOLAND_LOG_FORMAT` | `json` in prod, `plain` in dev | Tracing output format. Production deployments default to JSON for structured log aggregation; development defaults to ANSI-decorated text. Force either via `json` / `plain`. |
| `RUST_LOG` | unset | Tracing subscriber filter, e.g. `soland=info,salvo=warn` |

### OpenTelemetry tracing

OTLP trace export is a build-time opt-in to keep the default binary
free of the OpenTelemetry SDK. Build with `--features otel`, then set
`SOLAND_OTEL_EXPORTER=otlp` at runtime to export spans to your
collector. The recommended local collector setup is the
[OpenTelemetry Collector Contrib](https://github.com/open-telemetry/opentelemetry-collector-contrib)
distribution with an `otlp` receiver on `:4317` and your preferred
backend (Tempo, Jaeger, Honeycomb, ...) as the exporter. See
[DEPLOYMENT.md §7](DEPLOYMENT.md) for the production env-var matrix and
sample collector config.

## Local TLS

For local HTTPS development, use `mkcert`. It installs a local CA into your
OS/browser trust store and produces PEM files that soland can hand directly to
Salvo's rustls listener.

The embedded `did:webvh` provider needs a dotted host, so plain `localhost` is
not enough. The examples below use `local.host`, matching the checked-in `.env`
and the `local.host.pem` / `local.host-key.pem` file names.

1. Install `mkcert` and trust its local CA:

   ```bash
   mkcert -install
   ```

2. Generate a certificate for the local hostname:

   ```bash
   mkcert local.host
   ```

3. If `local.host` does not already resolve to loopback on your machine, add a
   hosts entry pointing it at `127.0.0.1`.

4. Configure soland to use the generated files:

   ```dotenv
   SOLAND_BIND=127.0.0.1:443
   SOLAND_PUBLIC_BASE_URL=https://local.host:443
   SOLAND_SERVICE_DID=did:web:local.host
   SOLAND_TLS_CERT_PATH=./local.host.pem
   SOLAND_TLS_KEY_PATH=./local.host-key.pem
   SOLAND_OBJECT_STORAGE_BACKEND=filesystem
   SOLAND_OBJECT_STORAGE_LOCAL_ROOT=../testdata
   SOLAND_DEVELOPMENT_MODE=true
   ```

5. Start the server:

   ```bash
   cargo run
   ```

If you choose a different hostname, update `SOLAND_PUBLIC_BASE_URL`,
`SOLAND_SERVICE_DID`, and the TLS file paths together. Use a host name that
contains a dot so embedded `did:webvh` URLs remain valid.

### Run local Caddy for coauth integration

For local coauth + soland testing, the checked-in `Caddyfile` terminates HTTPS
on port 443 and proxies:

```text
https://local.host      -> 127.0.0.1:8698
https://auth.local.host -> 127.0.0.1:7080
```

Start soland on `127.0.0.1:8698`, start coauth on `127.0.0.1:7080`, then run:

```bash
just caddy
```

If either host does not resolve to loopback on your machine, add both names to
your hosts file:

```text
127.0.0.1 local.host auth.local.host
```

When `SOLAND_DEVELOPMENT_MODE=false` (the default), submitted commits must use
production proof material — no `alg: none` or `dev-proof`, proof `payload_digest`
must match the canonical commit digest, the verification method must be rooted
in the commit author DID, and proof `domain`/`audience` must bind to
`SOLAND_SERVICE_DID`.

`GET /api/v1/identity/describe` exposes `did_webvh.providers[]` for coauth.
When the embedded provider is enabled, coauth can register through
`POST /api/v1/identity/webvh/register` with `Authorization: Bearer
<SOLAND_EMBEDDED_WEBVH_REGISTRATION_BEARER>`; soland then serves the DID
document and webvh log from `/webvh/{local_id}/did.json` and `.jsonl`. The
embedded DID uses the public `did:webvh:<scid>:<host>:webvh:<local_id>` path
rather than the internal registration API path.

Production authentication follows the Matrix/Palpo delegated-auth shape. A
client sends its coauth OAuth access token directly to soland as
`Authorization: Bearer <access_token>`. If the token is not a local dev session,
soland calls `SOLAND_OAUTH_INTROSPECTION_URL` with
`Authorization: Bearer <SOLAND_OAUTH_INTROSPECTION_BEARER>`, requires an active
token with `urn:contrix:principal-server:session.bind`, then maps
`org.contrix.principal_did` and `org.contrix.device_id` into the local
account/device view. The older `/api/v1/auth/session-grant/exchange` bridge is
kept as a legacy scaffold, not the primary login path.

Account subscribe and Events API cursors are structured `cx:cursor:` tokens
bound to the principal, device, service DID, filter hash, stream positions, and
expiry. `/api/v1/account/subscribe` resumes with `after`; `/api/v1/events`
paginates with `before` / `after`. Expired cursors fail with `cursor_expired`.

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

- `GET  /health` — liveness + DB / persistence probe (used as the Docker healthcheck)
- `GET  /readyz` — readiness probe for DB, boot migrations, introspection bearer config, and external webvh boot probe state
- `GET  /.well-known/contrix/openapi.json` and `.../openapi.yaml` — the
  generated OpenAPI 3.1 document from soland's Salvo route wiring
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

The current implementation has product-shaped auth/session, identity, events
log, device key, to-device, blob, directory, sync, and index surfaces.
PostgreSQL migrations and the persistence adapters are wired; in-memory mode is
the development fallback. Remaining production work is tracked in
[`../_todos.md`](../_todos.md) — reducer-backed projections, full policy ordering,
durable projection/device sub-stores, full E2EE client workflow, anti-enumeration, and
the complete federation/media/recovery/key-backup surfaces.

## Production Deployment Checklist

Before exposing soland to the public internet, walk every item below.
The same list is computed at runtime and surfaced on
`/health.hardening` (and `/api/v1/server/describe.hardening`) so sodmin's
`/hardening` dashboard can flag failing checks across the whole fleet.

- [ ] `SOLAND_DEVELOPMENT_MODE=false` (default — only flip to true on a loopback dev bind)
- [ ] TLS enabled (`SOLAND_TLS_CERT_PATH` / `SOLAND_TLS_KEY_PATH`, or terminated at the reverse proxy)
- [ ] CSP header configured at the reverse proxy
- [ ] CORS limited to the configured allowed origins (`SOLAND_CORS_ALLOW_ORIGIN`)
- [ ] Secrets in a secret manager (`SOLAND_ANCHORER_SIGNING_KEY`, OAuth introspection bearer)
- [ ] Log redaction enabled (default outside dev mode)
- [ ] Admin auth in production mode (`SOLAND_ADMIN_PRINCIPAL_DIDS` and/or `SOLAND_OAUTH_INTROSPECTION_URL`)
- [ ] Rate limit enabled (default; do not disable in production)
- [ ] Provider credential rotation scheduled (KeyStore + `rotate-signing-key`)
- [ ] `SOLAND_SEED_DEMO_DATA=false` (default — never on a federated production deployment)

## License

Apache-2.0 — see [LICENSE](LICENSE).

---

<!-- circle-rollout milestone pointer -->
> **Active milestone tracking** (local-only, gitignored): see
> `_soland_todos.md` in the parent `contrix-dev/` directory for the
> circle-rollout (CXP-0007) work item list and per-stage checkpoints.
