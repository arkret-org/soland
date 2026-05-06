# soland — Open Tasks

> Audit baseline: 2026-05-04. Reference implementation of `contrix-spec` v1
> (Salvo + Diesel/PostgreSQL + in-memory fallback). Completed work lives in
> `git log`; this file lists only **outstanding** tasks.
>
> Last refresh: 2026-05-06.

---

## P0 · Foundation gate (serial)

> Any of F2/F5/F6 left undone causes downstream rework or blocks CI.

| # | Task | Files | Blocks |
| --- | --- | --- | --- |
| **F2** | Upgrade `MemoryPersistenceStore` fallbacks for `contacts / space_meta / messages / blobs` to PgStore. Add trait + Pg + memory implementations for `push_devices / push_rules / presence / policy_documents / moderation_reports / audit_log / webrtc_sessions / key_backups / recovery_tickets / restore_state_snapshots / outbound_push_cache` and migrate the long-lived state currently held in `state.rs` mutexes. (`persistence.rs:531` `TODO(P0 durable-state)`.) | `src/persistence.rs`, `src/state.rs`, `migrations/*` | P1 federation/MIMI/recovery/key-backup |
| **F5** | **Integration-test hangs** — `account_contacts_and_space_lifecycle_workflow` and `admin_collection_surfaces_return_sodmin_shapes` (and ~8 more) hang under cargo test, even with `--test-threads=1`. Reproduce with `RUSTFLAGS="--cfg tokio_unstable" RUST_LOG=trace` + `tokio-console` or strip ratelimit / `wait_for_sync_token` middleware in a diff. | `tests/http_api.rs`, `src/ratelimit.rs`, `src/routing/mod.rs::wait_for_sync_token` | unblocks CI |
| **F6** | **Integration-test failure** — `auth_keys_device_messages_and_blobs_work` panics on `legacy_field_push_body["error"]["message"]` (gets `Null`); pre-existing on baseline. Reproduce + fix push-notify error envelope shape. | `src/routing/{keys,device_messages,blob,push}.rs` | unblocks CI |

---

## P1 · Domain expansion (parallelizable after F2)

### Stream A · Reducer kind handler coverage (21% → 80%+)

> Each sub-task is an independent PR. Projection state classified by spec
> `evaluation_class` (stateless / grant_local / space_state).

| # | Task | Files |
| --- | --- | --- |
| A2 | `cx.space.{join_rule, history_visibility, discovery, policy, policy_components, schema, plaintext_visible_services, history_sharing_policy, asset_privacy_policy, moderation_policy, media_service, tombstone, archive, freeze, upgrade, organization, child, parent, inheritance_policy}` projections → new `SpaceMetaState`, reducer fan-out. Covers spec B-15 / B-16 / B-21 (`kind=enclave` ⇒ `federation_policy=closed` default; `kind=board\|list` ⇒ `boundary_profile=container`). | `src/reducer.rs`, `src/state.rs::ProjectionState` |
| A3 | `cx.schema.{define,update}` + `cx.morph.{create,update,archive,restore}` projections → `SchemaRegistryState` / `MorphState` (independent PRs). | `src/reducer.rs` |
| A4 | `cx.view.{create,update,reconcile}` projection → `ViewState` (spec M-34: per-kind renderer enum schema-enforced). | `src/reducer.rs`, `src/wire.rs` |
| A5 | `cx.flow.{create,update,archive,restore,convert,move,reorder,branch.*}` projection → `FlowState` with fractional indexing. Apply spec B-19: `Message.branch` regex `^[a-z][a-z0-9_]{0,63}$`. | `src/reducer.rs`, `src/wire.rs` |
| A6 | `cx.capability.{grant,delegate,revoke,derived}` projection → `CapabilityState` (feeds `effective_grants`). | `src/reducer.rs` |
| A7 | `cx.policy.{set,rule,action}` projection → `PolicyState` (linked with Stream-D). | `src/reducer.rs` |
| A8 | `cx.invite.{create,cancel,accept,third_party,claim,revoke}` projection → `InviteState` (spec M-10: invite/notification `auth_refs`). | `src/reducer.rs` |
| A9 | `cx.account.{status,blocklist}` + `cx.account_data.set` projections (spec B-17: include `account.status / moderation.report / moderation.frank` in the state-event roster). | `src/reducer.rs` |
| A10 | `cx.moderation.{report,frank}` projection; coordinate with Stream-E moderation pipeline. | `src/reducer.rs` |
| A11 | `cx.audit.{accessed, ryw_receipt}` projection → `AuditReceiptState`; **register `cx.audit.ryw_receipt`** in the catalog (spec B-13). | `src/reducer.rs`, `contrix-spec/artifacts/registry/contract-catalog.json` |
| A12 | `cx.identity.{disclosure_policy,disclosure_receipt,presentation_request,presentation_response}` + `cx.did.proof` + `cx.session.grant` projections. | `src/reducer.rs` |
| A13 | `cx.device.{authorized,revoked,list_update}` projection → wire through to Stream-F device inventory. | `src/reducer.rs` |
| A14 | `cx.key.verification.*` (8 sub-kinds) projection → `KeyVerificationState` with SAS/QR single-use, device-signature binding, replay rejection (spec M-23). | `src/reducer.rs` |
| A15 | `cx.mls.{proposal,genesis,commit,commit_failed,welcome,keypackage,epoch}` projection → `MlsGroupState`; honor spec M-22 history-key revocation/destruction order. | `src/reducer.rs` |
| A16 | `cx.space_key.{share,withheld,share_audit}` projection → `SpaceKeyState`. | `src/reducer.rs` |
| A17 | `cx.member.state` + `cx.profile.{update,space_override}` projections. | `src/reducer.rs` |
| A18 | `cx.mimi.room_binding`, `cx.sovereign.did_policy`, `cx.organization.{discovery,moderation_policy}` projections. | `src/reducer.rs` |
| A19 | spec B-09: `redact` reducer must preserve `actor_seq` (currently `cleared` flattens attachments/mentions/relations; `hashes` must be cleared, not retained). | `src/reducer.rs` |

### Stream B · Authz / capability / policy

> B1 first (schema alignment), B2..B12 parallel afterward.

| # | Task | Files |
| --- | --- | --- |
| B1 | Align grant envelope shape (spec B-02) and unify constraint schema (spec B-04 + B-05); add `recurrence / max_duration / sensitive_fields / allowed_view_kinds / approval_threshold / condition.kind`; remove the `condition.when` string DSL. | `src/authz.rs`, `src/wire.rs`, spec mirror |
| B2 | Implement 11 missing constraints (each one PR): `field_access / scope_limitation / delegation_control / rate_limiting / approval_workflow / claim_based / accountability / encryption_requirement / container_move / visibility_control / resource_limit / edit_window / device_session`. | `src/authz.rs::evaluate_constraint` |
| B3 | Implement 10 `condition.kind` cases: `object_is_owned_by_actor / actor_is_assignee / ...`. Currently fail-open. | `src/authz.rs` |
| B4 | Add `evaluation_class: enum("stateless","grant_local","space_state","external")` to grant constraints and bucket caches accordingly (mirror in spec). | `src/authz.rs`, spec schema |
| B6 | Feed reducer `cx.capability.*` (A6) / `cx.invite.*` (A8) projections into `effective_grants()`. Currently only direct grants — no delegation/revocation chains. | `src/authz.rs`, `src/routing/authz.rs` |
| B7 | Invite ↔ grant linkage: accept-invite issues a grant; revoke-invite revokes the dangling grant; audit linked. | `src/routing/{authz,invite}.rs` |
| B8 | Capability lattice (auth_weight 11 levels) — currently flat boolean. Spec M-09 requires explicit causal_depth tie-break (v1.x or later). | `src/authz.rs` |
| B9 | Merge `policy_check` and `authz_check` — currently independent and inconsistent. | `src/routing/{authz,policy}.rs` |
| B10 | Execute obligations — currently echoed as JSON. Bind to reducer / write path / quarantine. | `src/routing/policy.rs` |
| B11 | Revocation beyond a single `grant.revoked` bool — add bulk/scope/time-window/CRL revocation; federation revocation fan-out (spec M-18). | `src/authz.rs` |
| B12 | Policy decision cache TTL by `evaluation_class` instead of hardcoded 5 min. | `src/authz.rs`, `src/state.rs` |

### Stream C · Federation & MIMI bridges

> Independent sub-tasks; production rollout depends on F2.

| # | Task | Files |
| --- | --- | --- |
| C1 | spec B-06: federation signature transcript fully on RFC 9421 (`@method / @target-uri / @authority / content-digest / created / expires`); drop legacy field names. | `src/routing/federation.rs` |
| C2 | `federation_push_operations` writes through to a persistent `federation_operations` table; idempotency key (spec M-20). | same + `persistence.rs` |
| C3 | `federation_pull_operations` reads from the persistent table with a cursor; survives restart (currently in-memory snapshot is wiped). | same |
| C4 | `federation_space_members` replaces hardcoded `"join"` placeholder with reducer membership state (depends on A2). | same |
| C5 | `federation_verify_actor` actually validates signatures / DID document / key set; returns `validation_class` enum, not a bool (spec M-19). | same |
| C6 | Revocation fan-out TTL + retry policy (spec M-18). | same |
| C7 | MIMI `room_update / notify / room_message` ingest into `cx.*` events instead of the audit log; remove demo "alice" mapping. | `src/routing/mimi.rs` |
| C8 | MIMI `consent_request / consent_update` via Stream-D consent state machine + persistence. | same |
| C9 | MIMI `key_material` actually issues / fetches a KeyPackage (links to A15); remove the `full_mls_keypackage_claim_not_implemented` literal. | same |
| C10 | MIMI `identifiers_query` via the real directory (Stream E); drop hardcoded alice. | same |
| C11 | MIMI `report_abuse` / `proxy_download` route through F2 persistent moderation/blob tables. | same |
| C12 | MIMI provider/protocol directory comes from config, not a static literal. | same |

### Stream D · Recovery / key-backup / restore-state

> The 46+ scaffold endpoints (`recovery/{discovery,readiness,live-snapshot,stack-bundle}`,
> `keys/backups/restore-state/*`, `keys/backups/restore-tickets/{ticket_id}/*`) all
> return `scaffold_*` placeholder fields with TODOs.
>
> D1 is the data-model gate; D2..D11 parallel afterward.

| # | Task | Files |
| --- | --- | --- |
| D1 | Design and land `RecoveryTicket` / `RestoreCheckpoint` / `RestoreApproval` / `RestoreExecutorRun` / `RestoreReceipt` data models + Pg/memory store + state machine (`pending → approved → enqueued → running → materialized → completed/failed/canceled`). | `persistence.rs`, new `src/recovery.rs`, `migrations/*` |
| D2 | `keys/backups` PUT/GET/DELETE/LIST move from in-process memory to D1's store; full schema validation (`cx.schema.key_backup.v1`, spec B-11). | `src/routing/key_backup.rs` |
| D3 | Restore-ticket lifecycle handlers: `describe / start / advance / resume / cancel / retry` (one PR each). | `src/routing/key_backup_restore.rs` |
| D4 | Restore approvals: `approvals/status / approvals/submit` — real reviewer authorization + quorum + audit. | same |
| D5 | Restore executor: `executor/{status,enqueue,start,complete}` — persistent worker lease/heartbeat + failure compensation. | same |
| D6 | Restore artifact endpoints: `result / receipt / bundle / activity / timeline / audit-feed / materialized-device-handoff` — drop synthetic dummy IDs. | same |
| D7 | Restore-state snapshots: `describe / export / import / durability / checkpoints` via D1 store + trust/freshness policy. | same |
| D8 | `recovery/discovery` real service discovery + DID-bound audience metadata. | `src/routing/recovery.rs` |
| D9 | `recovery/readiness` real storage / authz / policy / crypto health checks. | same |
| D10 | `recovery/live-snapshot` actor-scoped dashboard + pagination + privacy boundary. | same |
| D11 | `recovery/stack-bundle` assembled from real `recovery/contract-stack` output; remove inline path list. | same |
| D12 | spec M-28: `did:plc degraded_mirror_only` 7-day hard limit needs grace/extension. | `src/routing/identity.rs` |

### Stream E · Directory / search / moderation

> `search_organizations / search_actors / search_users / resolve_handle / resolve_organization`
> are all backed by the inline `demo_actors` fixture. `search_spaces` lacks a cursor.

| # | Task | Files |
| --- | --- | --- |
| E1 | F2 PgStore adds `actors`, `organizations`, `handles` tables + indexes; directory handlers read them. | `migrations/*`, `persistence.rs` |
| E2 | `search_spaces` cursor + ranking + privacy/visibility filters (drop hardcoded `public_only=false`). | `src/routing/directory.rs` |
| E3 | Anti-enumeration: rate limits / consent / fuzzy matching (spec security chapter). | same |
| E4 | Moderation pipeline: `moderation_report` writes through D1/F2 + async review workflow + reducer A10 link. | `src/routing/moderation.rs` |
| E5 | `moderation/report` SLA / status query (reporter-visible). | same |

### Stream F · Push / device / crypto / privacy

| # | Task | Files |
| --- | --- | --- |
| F-1 | spec B-14: DIDs must not appear in push payload / TURN username / push `sender`. Replace with Space-scoped pairwise pseudonym or ephemeral token; add MUST_NOT conformance tests. | `src/routing/{push,webrtc,push_outbound}.rs` |
| F-2 | `keys/upload / query / claim` via PgStore (`mod.rs` `TODO(P0 durable-state)`); revocation propagation linked with reducer A13. | `src/routing/keys.rs`, `persistence.rs` |
| F-3 | spec B-10: KeyPackage shape unified to `principal_id/device_id/keypackage_id/device_signature/expires_at`. | same |
| F-4 | spec B-11: merge `secret_storage` and `key_backup` into `cx.schema.key_backup.v1` + `domain` enum; HKDF info per domain. | `src/routing/key_backup.rs`, wire schema |
| F-5 | spec B-12: MLS GroupContext extension `cx_app_state_ref` allocated a private codepoint (0xF000–0xFFFF) and registered. | spec artifact + `src/wire.rs` |
| F-6 | spec B-22: encrypted attachment `key_ref` switched to object form `{algorithm, group_state_ref}`; drop string `"mls_epoch:42"`. | `src/routing/blob.rs`, `src/wire.rs` |
| F-7 | spec B-23: blob metadata adds `space_id` association + download/GC checks. | `src/routing/blob.rs`, `migrations/*` |
| F-8 | Push outbound bridge: replace process-memory cache (`TODO(push-outbound)` cluster) with a persistent snapshot store; etag/freshness, first-fetch persistence, fail-closed on contract drift. | `src/routing/push_outbound.rs` |
| F-9 | `auth/session-grant/exchange` and `push/register-device` `TODO(session-grant)` bridge: replace with coauth-backed introspection + audience binding + session-public-key proof verification. | `src/routing/{auth,push}.rs` |
| F-10 | WebRTC sessions / signals persistence (after F2); ICE config no longer returns an empty array. | `src/routing/webrtc.rs` |
| F-11 | profile/presence via the F2 presence store; presence/typing distinguish ephemeral vs durable channels. | `src/routing/profile.rs` |

---

## P2 · Sync / state-resolution / consistency

> Depends on P1-Stream-A; can run in parallel with P1-Stream-B/C/D.

| # | Task | Files |
| --- | --- | --- |
| S1 | `client_sync` actually maps `cx:cursor:` to reducer event sequence (`TODO(P0 sync)`). | `src/routing/sync.rs` |
| S2 | `snapshot-chunk` splits into deterministic multi-chunk (`TODO(P1 snapshot)`). | same |
| S3 | spec B-03: history_visibility (`invited` / `restricted`) — three divergences unified through the reducer. | `src/reducer.rs`, `src/routing/sync.rs` |
| S4 | spec M-15: every sync/directory response uses the `cx:space:` prefix (not `space:`). | grep + fix |
| S5 | spec M-16: formalize and validate `$ME` / `*` wildcard semantics in sync subscription. | `src/routing/sync.rs` |
| S6 | spec M-09 / M-10 follow-up: 4 state-resolution conformance vectors (with spec). | tests + spec |
| S7 | `index/debug/reducer` in-memory snapshot replaced with persistent projection (`TODO(P1 reducer-debug)`). | `src/routing/index.rs` |

---

## P3 · Code quality / observability / security audit

| # | Task | Files |
| --- | --- | --- |
| Q1 | Migrate every `#[endpoint]` handler to typed `JsonBody<T>` / `QueryParam<T>` extractors and `ToSchema` response types so per-route OpenAPI carries real request/response refs. Once every route is typed, drop the `SOLAND_EXTENSION_OPERATIONS` compatibility table in `src/lib.rs`. | `src/routing/*`, `src/lib.rs` |
| Q2 | spec M-01: remove `event_type` entirely; keep only `event_kind`. Drop the dead `aad_ambiguous_kind` error. | `src/wire.rs`, handlers, tests |
| Q3 | spec M-02..M-07: unify field-name drift (`principal_id/subject/holder_did`, `session_key_pub/session_public_key`, `Proof.kind`, `read_marker.id` pattern, …). | wire + handlers |
| Q5 | tracing: every handler entry `instrument(span)` carrying actor/space/event_kind. Currently almost no observable signal. | `src/routing/*` |
| Q6 | Rate-limit single-process → shared store (Pg/Redis); restart no longer wipes counters. | `src/ratelimit.rs` |
| Q7 | Tests split: `tests/http_api.rs` is one 5233-line / 42-test file. Carve into `tests/{auth,reducer,authz,federation,mimi,recovery,...}.rs` with shared `setup` in `tests/common/mod.rs`. | `tests/*` |
| Q8 | End-to-end conformance: run spec `artifacts/fixtures/*` through `submit → reduce → query` round-trip as the conformance gate. | `tests/conformance.rs` (new) |
| Q9 | `dev_login` / `admin/{resource}` and other dev-only paths gated behind a runtime hard guard (matching the SDK's "production" feature) instead of just `state.config.development_mode`. | `src/routing/{auth,admin}.rs` |
| Q10 | Security audit: every `accept` branch on the `SERVERX_DEVELOPMENT_MODE=false` path goes through real proof verification; back this with negative conformance tests. | `tests/security.rs` (new) |
| Q11 | CI: add `cargo clippy -- -D warnings` (already done), `cargo fmt --check` (already done), and `python ../contrix-spec/tools/artifact_pipeline.py check` (drift gate) — currently not wired. | `.github/workflows/*` |

---

## P4 · Robustness, security & operations

> Audit findings from a project-wide review on 2026-05-06. Items that landed
> in the same pass are recorded in git; only the open work is below.

### Security

| # | Task | Files |
| --- | --- | --- |
| Sec-2 | `dev_login` and `admin/{resource}` already `render_error(NOT_FOUND/FORBIDDEN)` when `development_mode=false`, but the route is still mounted. Either compile them out behind a `dev` Cargo feature or refuse to start the server with `development_mode=true` while `--bind 0.0.0.0:*`. Linked with Q9. | `src/routing/{admin,auth}.rs`, `src/lib.rs`, `Cargo.toml` |
| Sec-3 | The CORS handler trusts a single env-supplied `SERVERX_CORS_ALLOW_ORIGIN`. Validate that the origin is a well-formed URL and is not `*` when `allow_credentials=true` (currently the default). | `src/lib.rs::cors_handler_for_origin`, `src/config.rs` |
| Sec-6 | `src/main.rs` round-trips `DATABASE_URL` through `unsafe { std::env::set_var(...) }`. Drop the round-trip; pass the URL through `AppState` / `Db::connect(&url)` instead. | `src/main.rs`, `src/db.rs` |
| Sec-7 | Negative conformance test: every `dev-proof`/`alg=none` accept path returns 403 when `development_mode=false`. Pairs with Q10. | `tests/security.rs` (new) |

### Configuration & defaults

| # | Task | Files |
| --- | --- | --- |
| Cfg-1 | Surface common knobs that today are not configurable: `SERVERX_REQUEST_BODY_LIMIT`, `SERVERX_BLOB_MAX_BYTES`, `SERVERX_RATE_LIMITER_*`, `SERVERX_TRACING_FORMAT` (json vs pretty), `SERVERX_OTEL_ENDPOINT`. (`RUST_LOG` already routes through `EnvFilter`.) | `src/config.rs`, `src/main.rs`, `src/ratelimit.rs` |
| Cfg-2 | `AppConfig` currently has no `Display`/`Debug` redaction — service DID + base URL log fine but DB URL would leak credentials if added. Add a `redact_database_url()` helper before logging. | `src/config.rs`, `src/main.rs` |
| Cfg-3 | Validate `SERVERX_BLOB_ROOT` at startup — the directory must exist, be writable, and not be the system temp on production. Today a missing directory only fails on the first upload. | `src/config.rs` or `src/main.rs` |

### Deployment & operations

| # | Task | Files |
| --- | --- | --- |
| Dep-2 | `Dockerfile` doesn't yet declare `HEALTHCHECK`; the example block lives in `DEPLOYMENT.md` only. Add an inline directive that defers to `/health`. | `Dockerfile` |
| Dep-4 | `Dockerfile` runs as UID 10001 but doesn't `chown` the blob-root; document the bind-mount permission requirement OR mkdir + chown in the entrypoint. | `Dockerfile` |
| Dep-5 | A `docker-compose.yml` for local development (postgres + soland + adminer) so contributors don't need to set up DB by hand. | `docker-compose.yml` (new) |
| Dep-6 | `/metrics` Prometheus endpoint — Stream-Q5 covers tracing spans, but a separate counter/histogram surface is table stakes. | new module + `src/lib.rs` |

---

## Quick status (2026-05-06)

- **Code**: `src/` ~28K LOC; `tests/http_api.rs` 5.2K LOC / 42 tests.
- **Routes**: ~180 HTTP routes wired; many remain scaffold/echo (recovery,
  key-backup restore, push outbound bridge, MIMI, directory).
- **Persistence**: PgStore covers `accounts / sessions / devices /
  federation_transactions`; everything else falls back to MemoryStore — process
  restart wipes state.
- **Reducer**: 28 of 130 registered event kinds are projected (~21%). MLS,
  key-verification, schema/morph, view, flow, capability, policy,
  identity-disclosure, audit, invite, agent, applet, call: no projection.
- **Authz**: 3 / 14 constraints implemented; 0 / 10 `condition.kind` cases;
  invite ↔ grant ↔ policy not linked; obligations are inert.
- **OpenAPI**: components seeded from contrix-sdk's `register_contrix_oapi_components`;
  routes discovered via `merge_router(&router)`. Per-handler typed extractors
  pending (Q1).
- **Spec drift**: `contrix-spec/_report.md` lists 23 BLOCKING + 30+ MAJOR; ~14
  BLOCKING land in the server (B-02/03/05/06/07/09/10/11/12/13/14/17/18/22/23).
- **CI**: 76/76 lib unit tests pass; 31 integration tests pass; 1 pre-existing
  failure (F6) + ~10 pre-existing hangs (F5) block green CI.

---

## Parallel-schedule guidance

| Sprint | Streams that can run in parallel |
| --- | --- |
| **Sprint 1 (foundation gate)** | F2 / F5 / F6 in parallel; P4 robustness items (Sec / Cfg / Dep / Pkg / CI) can mostly run on their own track |
| **Sprint 2 (domain expansion)** | A · B · C · D · E · F (six streams); some P2 sub-tasks (S3 / S4 / S5) ride along |
| **Sprint 3 (consistency + Q)** | A19 + S1 / S2 / S6 / S7 + Q1..Q11 |

**Hard ordering constraints:**

- Stream A reducer changes feed Stream B's effective-grants → A merges first, B follows.
- Stream C's `federation_space_members` requires A2 (`SpaceMetaState`) and reducer membership projection.
- Stream D-1 (`RecoveryTicket` model) gates D2..D11.
- Stream F-2 (PgStore key store) gates A13/A14/A15 reducer write-throughs.
- Q1 (typed `#[endpoint]` extractors) is independent of P1; coordinate rebase frequency.

---

## Out of scope (v1.x backlog)

- Reshape `auth_weight` 11-level scale into a `(governance_layer, authority_kind)` lattice (B8 is just a placeholder).
- spec M-38 / M-39 / M-40: applet namespace, agent endpoint lifecycle, MIMI room_binding lifecycle.
- Multi-region / cross-service deployment (soland is a single-process reference).
- Full IANA codepoint application (B-12 only assigns the private-use block).
