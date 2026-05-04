# soland

Cross-platform Contrix reference server built with Salvo, PostgreSQL, and Diesel.

## Run

```powershell
cargo run -- --bind 127.0.0.1:8787
```

`DATABASE_URL` is optional for local development. Without it, soland runs with an in-memory repository and demo Space data while keeping the same HTTP API.

When `SERVERX_DEVELOPMENT_MODE=false`, submitted commits must use production proof material: no `alg: none` or `dev-proof`, proof `payload_hash` must match the canonical commit digest, the verification method must be rooted in the commit author DID, and proof `domain`/`audience` must bind to `SERVERX_SERVICE_DID`.

Client sync `next_batch` cursors are structured `cx:cursor:` tokens bound to the principal, device, service DID, filter hash, stream positions, and expiry. Passing `since` returns incremental timeline events and expired cursors fail with `sync_token_expired`.

Development bearer sessions are stored server-side by service-bound SHA-256 token hash, not by plaintext token. Logout records `revoked_at` and revoked sessions are rejected on later requests. To-device messages remain deliverable across duplicate syncs until the client presents a cursor with the acknowledged to-device position. Blob downloads require a bearer session plus a `purpose` query parameter; blobs are visible to the uploader or to members of the blob Space when one is bound at upload time.

The v1 primary write path is the signed Event Envelope API: `GET /api/v1/events/describe` declares the active event registry, schema/reducer profiles, and limits, and `POST /api/v1/events` accepts one canonical Event Envelope in the minimal profile. The `/api/v1/repo/*` endpoints remain available as a local legacy adapter, not as the only or canonical shared-history path.

Federation transaction IDs are recorded per origin with canonical request digests. Replaying the same `(origin, txn_id)` and body returns the stored response, while reusing the transaction ID with different content returns a conflict; PostgreSQL mode persists these replay records. Blob uploads normalize MIME types and filenames, enforce per-upload/account/Space quotas, and reject plaintext blobs in private Spaces unless this service is listed in `plaintext_visible_services`.

## Configuration

- `--bind` / `SERVERX_BIND`: listen address, default `127.0.0.1:8787`.
- `SERVERX_PUBLIC_BASE_URL`: advertised base URL.
- `SERVERX_SERVICE_DID`: service DID, default `did:web:soland.local`.
- `DATABASE_URL`: enables PostgreSQL and runs embedded Diesel migrations at startup.
- `SERVERX_BLOB_ROOT`: filesystem root reserved for blob storage.
- `SERVERX_CORS_ALLOW_ORIGIN`: optional explicit CORS allow-origin for browser clients; credentials, common Contrix headers, and preflight requests are supported only for that origin.
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
- `GET /api/v1/sync/backfill/gap`
- `GET /api/v1/sync/snapshot-head`
- `GET /api/v1/sync/snapshot-chunk`
- `GET /api/v1/events/describe`
- `POST /api/v1/events`
- `GET /api/v1/events/{event_id}`
- `POST /api/v1/events/batch-get`
- `GET /api/v1/events`
- `GET /api/v1/events/frontier`
- `GET /api/v1/directory/describe`
- `POST /api/v1/directory/search-spaces`
- `POST /api/v1/directory/resolve-space`
- `GET /api/v1/index/describe`
- `GET /api/v1/index/debug/reducer`
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
- `GET /api/v1/admin/{actors|spaces|devices|capabilities|federation|applets|agents|reports|invite-tokens|audit|policy|media}`
- `GET /api/v1/profile/presence`
- `POST /api/v1/push/register-device`
- `POST /api/v1/devices/pairing-challenge`
- `POST /api/v1/devices/authorize-pairing`
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
- `GET /.well-known/mimi-protocol-directory`
- `GET /api/v1/mimi/provider-directory`
- `POST /api/v1/mimi/key-material`
- `MIMI interop note:` the following `/api/v1/mimi/rooms/{room_id}` routes are external MIMI surfaces; their `room_id` is not the removed Contrix core `cx.room.*` wire contract.
- `PUT /api/v1/mimi/rooms/{room_id}/update`
- `POST /api/v1/mimi/rooms/{room_id}/notify`
- `POST /api/v1/mimi/rooms/{room_id}/messages`
- `GET /api/v1/mimi/rooms/{room_id}/group-info`
- `POST /api/v1/mimi/consent/request`
- `POST /api/v1/mimi/consent/update`
- `POST /api/v1/mimi/identifiers/query`
- `POST /api/v1/mimi/report-abuse`
- `POST /api/v1/mimi/proxy-download`

Protocol behavior should be read against the Chinese Contrix specification and generated `artifacts/` contracts. The old English `contrix-spec/en/...` references are not the source of truth for new v1 work.

The current implementation has product-shaped auth/session, identity, repo adapter, device key, to-device, blob, directory, sync, and index surfaces. PostgreSQL migrations and the repo adapter are wired; in-memory mode is kept as the development fallback. Remaining production work is tracked in `_todos.md`, especially reducer-backed projections, full policy ordering, durable device/blob stores, full E2EE client workflow, anti-enumeration, and complete federation/media surfaces.
