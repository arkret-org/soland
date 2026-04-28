# serverx Product TODOs

本项目为对 E:\Works\contrix-dev\contrix-spec 协议的实现. 本程序为后端实现.

## Product Baseline

- [x] Scaffold Salvo + Diesel/PostgreSQL service with Contrix SDK dependency.
- [x] Implement service discovery, health, sync, directory, repo submit, index query, and broader protocol skeleton endpoints.
- [ ] Replace demo-only responses with durable product behavior and protocol-validated state transitions.
- [x] Add configuration model for bind address, public base URL, service DID, DB URL, blob storage root, CORS, and development mode.
- [x] Add standard Contrix error envelope for every endpoint, including 404/405, validation errors, auth failures, rate limits, and conflicts.
- [x] Add request validation helpers for DID, Space ID, Device ID, cursor, limits, and required-one-of fields.
- [ ] Add structured tracing spans with request IDs and operation IDs.

## Primary Business Workflows

### Account and Device Onboarding

- [x] Design contract tests for account registration, duplicate registration, login/session issuance, current-account lookup, device binding, key upload, and device message bootstrap.
- [x] Implement product account registration endpoint that creates a DID-scoped local account record.
- [x] Implement current-account endpoint backed by authenticated session.
- [x] Ensure login requires an existing account outside development-only bootstrap mode.
- [x] Add session revocation / logout workflow.

### Contacts and Discovery

- [x] Design contract tests for handle resolution, contact request, accept/reject, contact listing, and anti-enumeration failures.
- [x] Implement contact request and response endpoints.
- [x] Implement authenticated contact list endpoint.
- [x] Enforce accepted-contact visibility for private actor lookup.

### Space Lifecycle and Membership

- [x] Design contract tests for creating a Space, inviting/joining members, listing member-visible Spaces, kicking a member, leaving a Space, deleting a Space, and ensuring deleted Spaces disappear from sync/directory/index.
- [x] Implement Space create endpoint that writes directory/index projection state.
- [x] Implement Space member add/invite endpoint with owner/admin checks.
- [x] Implement Space member remove/kick endpoint with owner/admin checks.
- [x] Implement Space delete endpoint with owner checks and tombstone filtering.
- [ ] Add reducer operations for membership changes and Space lifecycle events.

### Messaging and Media Workflow

- [x] Design contract tests for signed commit message publish, client sync receipt, backfill, attachment upload/hash check, E2EE opaque payload, and push wakeup.
- [x] Add helper endpoint or documented client flow for publishing encrypted message operations through signed commits.
- [x] Project message operations into thread, inbox, search, and client sync projections.
- [x] Project message operations into notification indexes.

### Moderation and Policy Workflow

- [ ] Design contract tests for report submission, policy check, capability denial, member kick/ban, deleted target behavior, and moderator visibility.
- [ ] Implement basic policy order: auth/session, device, capability, policy, reducer.

## Database and Storage

- [x] Add Diesel migrations for repos, operations, commits, spaces, events, sessions, devices, keys, blobs, push devices, reports, presence, account data, and notifications.
- [x] Implement PostgreSQL repository adapter for operations and commit chains.
- [ ] Implement PostgreSQL space/index projections with reducer state snapshots.
- [ ] Implement PostgreSQL device/key/message queues.
- [ ] Implement PostgreSQL blob metadata and filesystem blob content storage.
- [x] Keep in-memory mode as a tested development fallback with behavior matching PostgreSQL mode.
- [x] Add startup migration checks and fail-fast diagnostics.

## Identity, Auth, and Sessions

- [x] Implement `GET /api/v1/identity/describe`.
- [x] Implement `POST /api/v1/identity/resolve`.
- [x] Implement `GET /api/v1/identity/document`.
- [x] Implement `GET /api/v1/identity/log`.
- [x] Implement `POST /api/v1/identity/submit-did-operation`.
- [x] Implement `GET /api/v1/identity/receipts`.
- [x] Implement development auth endpoints for session issuance without pretending to be protocol identity root.
- [x] Verify bearer sessions on protected endpoints.
- [x] Bind sessions to DID + Device ID + expiry.
- [x] Reject auth material in query strings.

## Repo, Operations, and Reducer Logic

- [x] Implement `GET /api/v1/repo/describe` from real repo state.
- [x] Implement `GET /api/v1/repo/commits` with pagination.
- [x] Implement `GET /api/v1/repo/commit` with optional operation expansion.
- [x] Implement `POST /api/v1/repo/operations` with visibility filtering.
- [x] Implement `POST /api/v1/repo/sync` with cursor pagination and dedupe.
- [x] Implement `POST /api/v1/repo/submit-commit` with operation preloading, commit CAS, proof validation, and author sequence checks.
- [ ] Update index projections transactionally after accepted commits.
- [x] Add helper endpoint or client workflow for publishing encrypted message operations through signed commits.
- [ ] Enforce operation payload validation and known operation family semantics.
- [ ] Add reducer-backed state for messages, reactions, redactions, membership, capabilities, read markers, and entities.

## Sync and Index

- [x] Implement `POST /api/v1/sync` from stored projections and per-device queues.
- [x] Implement `GET /api/v1/sync/describe`.
- [x] Implement `GET /api/v1/sync/backfill` from repo operation history.
- [ ] Implement `GET /api/v1/sync/snapshot-head` with signed snapshot manifest.
- [x] Implement `GET /api/v1/sync/subscribe` via long-poll frames.
- [x] Implement `GET /api/v1/index/describe`.
- [x] Implement `GET /api/v1/index/entity`.
- [x] Implement `POST /api/v1/index/query`.
- [x] Implement `GET /api/v1/index/thread`.
- [x] Implement `GET /api/v1/index/notifications`.
- [x] Implement `GET /api/v1/index/inbox`.
- [x] Implement `POST /api/v1/index/search`.
- [x] Implement `GET /api/v1/index/space-hierarchy`.

## Directory and Discovery

- [x] Implement `GET /api/v1/directory/describe`.
- [x] Implement `POST /api/v1/directory/search-spaces`.
- [x] Implement `POST /api/v1/directory/resolve-space`.
- [x] Implement `POST /api/v1/directory/search-organizations`.
- [x] Implement `POST /api/v1/directory/resolve-organization`.
- [x] Implement `POST /api/v1/directory/search-actors`.
- [x] Implement `GET /api/v1/directory/search-users`.
- [x] Implement `POST /api/v1/directory/resolve-handle`.
- [ ] Enforce discoverability levels and anti-enumeration behavior.

## E2EE, Devices, and Keys

- [x] Implement `PUT /api/v1/device_messages/{txn_id}` with idempotent to-device queues.
- [x] Implement `GET /api/v1/device_messages` for current authenticated device.
- [x] Implement `POST /api/v1/keys/upload`.
- [x] Implement `POST /api/v1/keys/query`.
- [x] Implement `POST /api/v1/keys/claim` with atomic one-time-key consumption.
- [x] Store MLS key packages, fallback keys, and device signatures.
- [x] Persist uploaded fallback keys and device signatures with the queryable device key record.
- [x] Preserve encrypted payloads as opaque server-forwarded data.
- [x] Add tests proving server cannot decrypt E2EE message bodies and still syncs metadata.

## Blob, Media, Push, Moderation, Policy

- [x] Implement `POST /api/v1/blob/upload` with hash validation, quota checks, and metadata.
- [x] Implement `HEAD /api/v1/blob/get`.
- [x] Implement `GET /api/v1/blob/get` with range-safe download and hash headers.
- [x] Implement `POST /api/v1/push/register-device`.
- [x] Implement `POST /api/v1/push/unregister-device`.
- [x] Implement `POST /api/v1/push/notify`.
- [x] Implement `POST /api/v1/authz/check`.
- [x] Implement `GET /api/v1/authz/effective-grants`.
- [x] Implement `GET /api/v1/authz/invites`.
- [x] Implement `POST /contrix/v1/check`.
- [x] Implement `POST /api/v1/moderation/report`.
- [ ] Implement basic policy order: auth/session, device, capability, policy, reducer.

## Tests and Documentation

- [x] Add endpoint contract tests for every implemented path.
- [ ] Add PostgreSQL integration tests gated by `DATABASE_URL`.
- [x] Add client/server E2EE message workflow test.
- [ ] Add repo conflict, idempotency, pagination, and visibility tests.
- [x] Cover repo commit operation expansion, CAS conflict, idempotent to-device delivery, pagination, backfill, and subscribe smoke paths.
- [x] Add docs for configuration, database setup, auth model, E2EE limits, and production caveats.
- [x] Run `cargo fmt`, `cargo test`, server HTTP smoke, and client contract tests before marking complete.
