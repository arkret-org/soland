# soland

Cross-platform Contrix reference server built with Salvo, PostgreSQL, and Diesel.

## Run

```powershell
cargo run -- --bind 127.0.0.1:8787
```

`DATABASE_URL` is optional for local development. Without it, soland runs with an in-memory repository and demo Space data while keeping the same HTTP API.

When `SERVERX_DEVELOPMENT_MODE=false`, submitted commits must use production proof material: no `alg: none` or `dev-proof`, proof `payload_hash` must match the canonical commit digest, the verification method must be rooted in the commit author DID, and proof `domain`/`audience` must bind to `SERVERX_SERVICE_DID`.

## Configuration

- `--bind` / `SERVERX_BIND`: listen address, default `127.0.0.1:8787`.
- `SERVERX_PUBLIC_BASE_URL`: advertised base URL.
- `SERVERX_SERVICE_DID`: service DID, default `did:web:soland.local`.
- `DATABASE_URL`: enables PostgreSQL and runs embedded Diesel migrations at startup.
- `SERVERX_BLOB_ROOT`: filesystem root reserved for blob storage.
- `SERVERX_CORS_ALLOW_ORIGIN`: configured CORS origin placeholder.
- `SERVERX_DEVELOPMENT_MODE`: enables development auth bootstrap.

## API

- `GET /health`
- `GET /api/v1/server/describe`
- `POST /api/v1/account/register`
- `GET /api/v1/account/me`
- `POST /api/v1/auth/dev-login`
- `POST /api/v1/auth/logout`
- `POST /api/v1/contacts/request`
- `POST /api/v1/contacts/respond`
- `GET /api/v1/contacts`
- `POST /api/v1/spaces`
- `DELETE /api/v1/spaces/{space_id}`
- `POST /api/v1/spaces/{space_id}/members`
- `DELETE /api/v1/spaces/{space_id}/members/{member_did}`
- `POST /api/v1/messages/send`
- `GET /api/v1/identity/describe`
- `POST /api/v1/identity/resolve`
- `GET /api/v1/identity/document`
- `GET /api/v1/identity/log`
- `POST /api/v1/identity/submit-did-operation`
- `GET /api/v1/identity/receipts`
- `GET /api/v1/sync/describe`
- `POST /api/v1/sync`
- `GET /api/v1/sync/subscribe`
- `GET /api/v1/sync/backfill`
- `GET /api/v1/sync/snapshot-head`
- `GET /api/v1/directory/describe`
- `POST /api/v1/directory/search-spaces`
- `POST /api/v1/directory/resolve-space`
- `GET /api/v1/index/describe`
- `POST /api/v1/index/query`
- `GET /api/v1/repo/describe`
- `GET /api/v1/repo/commits`
- `GET /api/v1/repo/commit`
- `POST /api/v1/repo/operations`
- `POST /api/v1/repo/sync`
- `POST /api/v1/repo/submit-commit`
- `POST /api/v1/authz/check`
- `GET /api/v1/authz/effective-grants`
- `GET /api/v1/authz/invites`
- `GET /api/v1/profile/presence`
- `POST /api/v1/push/register-device`
- `POST /api/v1/push/unregister-device`
- `POST /api/v1/keys/upload`
- `POST /api/v1/keys/query`
- `POST /api/v1/keys/claim`
- `PUT /api/v1/device_messages/{txn_id}`
- `GET /api/v1/device_messages`
- `POST /api/v1/blob/upload`
- `HEAD /api/v1/blob/get`
- `GET /api/v1/blob/get`
- `POST /api/v1/moderation/report`

These paths follow `contrix-spec/en/sync/service-http-binding.md`.

The current implementation has product-shaped auth/session, identity, repo adapter, device key, to-device, blob, directory, sync, and index surfaces. PostgreSQL migrations and the repo adapter are wired; in-memory mode is kept as the development fallback. Remaining production work is tracked in `_todos.md`, especially reducer-backed projections, full policy ordering, durable device/blob stores, full E2EE client workflow, anti-enumeration, and complete federation/media surfaces.
