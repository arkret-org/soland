# Soland `/api/v1` ↔ contrix-spec Conformance Report

> Generated 2026-05-22. Cross-reference of every HTTP endpoint mounted under
> `/api/v1/*`, `/contrix/v1/*`, and `/api/admin/v1/*` in `soland` against
> `contrix-spec/spec/v1/artifacts/openapi/contrix-service-api.openapi.yaml`
> (the canonical Contrix Service API, 80 path entries / ~85 (path, method)
> pairs after splitting GET/HEAD on `/blob/get`).

## Executive Summary

| Category | Count | Notes |
|---|---:|---|
| Total HTTP endpoints in soland | ~155 (path, method) pairs | Includes `/api/v1`, `/api/admin/v1`, `/contrix/v1`, `/.well-known/*` |
| Endpoints in spec and implemented (path + method match) | **42** | Core data path is well covered |
| Endpoints in spec but path-param name diverges | **4** | All MIMI: `{flow_id}` vs `{room_id}` |
| Endpoints in spec but **not implemented** in soland | **~21** | See §6 |
| Endpoints in soland but **not in spec**, marked `cx.extension.soland.*` | **~36** | Deployment-local, intentional |
| Endpoints in soland but **not in spec** and **no operation_id** | **~50** | Mostly admin/CRUD/sync helpers — see §4 / §5 for the per-row recommendation |
| Operator-only admin under `/api/admin/v1` | **14** | Out of scope for the federated spec |
| Federated/cross-server endpoints | 2 (`/contrix/v1/check`, `/contrix/v1/ice-config`) | Both in spec |

Headline findings:

1. **Core data plane (events/account/snapshot/projection/identity/authz/blob/push/mimi/keys) is well-aligned**. Operation IDs use the canonical `cx.*` namespace.
2. **MIMI path-param naming is off-spec** — soland uses `{room_id}` everywhere; spec uses `{flow_id}` (4 PUT/POST/GET endpoints). Decision needed: rename param, or change spec.
3. **`POST /events/query` is missing in soland.** Spec defines both `GET /events` and `POST /events/query` (the latter is `cx.events.query_post` for large filter bodies). soland only implements GET.
4. **`/identity/submit-did-operation`, `/device_messages`, `/blob/presign`, `/directory/{announce,withdraw,subscribe,private-contact-discovery}`, `/keys/keypackages/{consume,revoke}` are all in the spec but not implemented in soland.**
5. **Auth bootstrapping diverges from spec.** Spec defines `auth/account/session-grants`, `auth/account/device-pair`, `auth/account/oidc/callback`; soland has its own ` auth/dev-login`, `auth/session-grant/exchange`, `auth/logout`, `auth/bridge/describe`. These should either be reconciled into the spec, or moved into a soland extension namespace.
6. **`/api/v1/admin/*` is heavily soland-specific.** The spec only defines 4 admin endpoints (`server/status`, `accounts/{id}/status`, `devices/{id}/revoke`, `moderation/queue`). soland has 27 admin endpoints, none of those four. The soland admin surface is internal operator UX, and the spec's admin surface for federated identity is unimplemented.
7. **`/api/admin/v1/*`** (anchor DAG / multisig / bottom / GC) is deliberately a different prefix — internal operator tooling, never federated. These should stay out of the federated spec.
8. **`/extensions/*` (soland) vs `/applet/*` (spec) are different surfaces.** Soland's `extensions/{manifests,bots,tsp}` is the **core-server-side** of applet integration (manifest verifier, ghost/bot registry, TSP audit). Spec's `applet/*` is the **applet-side** of the same boundary (the API an applet exposes for the core to call into). Both surfaces should coexist in the spec.
9. **`/api/v1/conformance/*`** (6 endpoints) is a test-vector helper, not a runtime API. Should either be gated behind a feature flag in production builds or documented in the spec as `cx.conformance.*` (test-time only).
10. **`/api/v1/spaces/{space_id}/export`** and **`/api/v1/spaces/{space_id}`** are not in the spec. The space lifecycle data is exposed via `cx.projection.spaces`, but a per-space "describe / export" endpoint is missing from the canonical spec.

---

## 1. Methodology

- **Spec inventory**: parsed all top-level keys under `paths:` in
  `contrix-spec/spec/v1/artifacts/openapi/contrix-service-api.openapi.yaml`
  (line 99 `servers: - url: https://{host}/api/v1`, so every entry like
  `/events/{event_id}` corresponds to soland's `/api/v1/events/{event_id}`,
  except `/contrix/v1/ice-config` which sits at the literal `/contrix/v1`
  prefix).
- **Soland inventory**: walked `src/routing/{system,identity,spaces,realms,
  federation,events,access,admin,interop,conformance,mls,extensions,
  realm_policy}/*` for `Router::with_path(...).{get,post,put,delete,head,
  patch,goal}(handler)` registrations, and cross-checked against the
  `SOLAND_EXTENSION_OPERATIONS` table in `src/routing/mod.rs` (lines
  255-865) which lists operation IDs and summaries.
- **Match policy**: `(path, method)` tuples are matched literally; path
  parameters compare on **position**, not name (so `{flow_id}` ≡ `{room_id}`
  but is flagged as a name divergence under §3).
- **Operation-ID naming**: `cx.foo.bar` = spec-canonical; `cx.extension.soland.*`
  = deployment-local soland extension (explicitly out-of-spec by design);
  endpoints with no `operation_id` in the extension table are flagged as
  **needs classification**.

---

## 2. Endpoints in spec **and** implemented in soland (conforming)

These are good — both sides agree on path + method. (Operation IDs come from
the spec; soland either registers the same ID via `#[endpoint(operation_id =
"...")]` or via `SOLAND_EXTENSION_OPERATIONS`.)

| Path | Method | operation_id |
|---|---|---|
| `/api/v1/server/describe` | GET | `cx.server.describe` |
| `/api/v1/identity/resolve` | POST | `cx.identity.resolve` |
| `/api/v1/identity/document` | GET | `cx.identity.get_document` |
| `/api/v1/identity/log` | GET | `cx.identity.get_log` |
| `/api/v1/identity/describe` | GET | `cx.identity.describe` |
| `/api/v1/identity/receipts` | GET | `cx.identity.get_receipts` |
| `/api/v1/events` | POST | `cx.events.submit` |
| `/api/v1/events` | GET | `cx.events.query` |
| `/api/v1/events/describe` | GET | `cx.events.describe` |
| `/api/v1/events/subscribe` | GET | `cx.events.subscribe` |
| `/api/v1/events/{event_id}` | GET | `cx.events.get` |
| `/api/v1/events/resolve` | POST | `cx.events.resolve` |
| `/api/v1/events/frontier` | GET | `cx.events.frontier` |
| `/api/v1/account/describe` | GET | `cx.account.describe` |
| `/api/v1/account/subscribe` | GET | `cx.account.subscribe` |
| `/api/v1/snapshot/head` | GET | `cx.snapshot.head` |
| `/api/v1/projection/spaces` | GET | `cx.projection.spaces` |
| `/api/v1/projection/flows` | GET | `cx.projection.flows` |
| `/api/v1/projection/morphs` | GET | `cx.projection.morphs` |
| `/api/v1/directory/describe` | GET | `cx.directory.describe` |
| `/api/v1/directory/resolve-handle` | POST | `cx.directory.resolve_handle` |
| `/api/v1/directory/search-realms` | POST | `cx.directory.search_realms` |
| `/api/v1/directory/resolve-realm` | POST | `cx.directory.resolve_realm` |
| `/api/v1/directory/search-organizations` | POST | `cx.directory.search_organizations` |
| `/api/v1/directory/resolve-organization` | POST | `cx.directory.resolve_organization` |
| `/api/v1/directory/search-actors` | POST | `cx.directory.search_actors` |
| `/api/v1/directory/search-users` | POST | `cx.directory.search_users` |
| `/api/v1/blob/upload` | POST | `cx.blob.upload` |
| `/api/v1/blob/get` | GET | `cx.blob.get` |
| `/api/v1/blob/get` | HEAD | `cx.blob.head` |
| `/api/v1/push/register-device` | POST | `cx.push.register_device` |
| `/api/v1/push/unregister-device` | POST | `cx.push.unregister_device` |
| `/api/v1/push/notify` | POST | `cx.push.notify` |
| `/api/v1/authz/check` | POST | `cx.authz.check` |
| `/api/v1/authz/effective-grants` | GET | `cx.authz.get_effective_grants` |
| `/api/v1/authz/invites` | GET | `cx.authz.get_invites` |
| `/api/v1/keys/upload` | POST | `cx.keys.upload` |
| `/api/v1/keys/query` | POST | `cx.keys.query` |
| `/api/v1/keys/claim` | POST | `cx.keys.claim` |
| `/api/v1/keys/keypackages/upload` | POST | `cx.keys.keypackages.upload` |
| `/api/v1/keys/keypackages/claim` | POST | `cx.keys.keypackages.claim` |
| `/api/v1/keys/backups/{backup_id}` | PUT/GET/DELETE | `cx.keys.backups.{put,get,delete}` |
| `/api/v1/keys/backups` | GET | `cx.keys.backups.list` |
| `/api/v1/moderation/report` | POST | `cx.moderation.report` |
| `/api/v1/mimi/provider-directory` | GET | `cx.mimi.provider_directory` |
| `/api/v1/mimi/key-material` | POST | `cx.mimi.key_material` |
| `/api/v1/mimi/consent/request` | POST | `cx.mimi.request_consent` |
| `/api/v1/mimi/consent/update` | POST | `cx.mimi.update_consent` |
| `/api/v1/mimi/identifiers/query` | POST | `cx.mimi.identifier_query` |
| `/api/v1/mimi/report-abuse` | POST | `cx.mimi.report_abuse` |
| `/api/v1/mimi/proxy-download` | POST | `cx.mimi.proxy_download` |
| `/api/v1/policy/check` | POST | `cx.policy.check` |
| `/contrix/v1/check` | POST | `cx.policy.check` (alias of above) |
| `/contrix/v1/ice-config` | POST | `cx.media.ice_config` |

**Note:** `/contrix/v1/check` is registered in soland but **not in the spec**
(only `/policy/check` is). Either remove the alias or document it. Spec
treats `cx.policy.check` as the canonical operation; the federated `/contrix/v1`
prefix is normally reserved for cross-server S2S transport (`/contrix/v1/ice-config`).

---

## 3. Endpoints in spec, implemented in soland, **with parameter divergence**

### 3.1 MIMI room path parameter: `{flow_id}` (spec) vs `{room_id}` (soland)

| Spec path | Method | Soland path | Severity |
|---|---|---|---|
| `/mimi/rooms/{flow_id}/update` | PUT | `/api/v1/mimi/rooms/{room_id}/update` | Low (path-param name only — value is the same Contrix Flow ID) |
| `/mimi/rooms/{flow_id}/notify` | POST | `/api/v1/mimi/rooms/{room_id}/notify` | Low |
| `/mimi/rooms/{flow_id}/messages` | POST | `/api/v1/mimi/rooms/{room_id}/messages` | Low |
| `/mimi/rooms/{flow_id}/group-info` | GET | `/api/v1/mimi/rooms/{room_id}/group-info` | Low |

**Recommendation**: Path-param names are not part of the URL, but they are
visible in OpenAPI client SDKs (the generated parameter name follows the
spec). To stay consistent with the rest of the Contrix terminology (where
"MIMI room ↔ Contrix flow"), **rename the soland path param to `flow_id`**.
Mechanical rename — no behavioral change. See `src/routing/interop/mimi.rs`.

### 3.2 `GET /api/v1/events` query semantics divergence

`src/routing/events/sync.rs:1253` (`events_query`) implements:
- accepts `realms[]` / `actors[]` (spec-canonical) **plus** soland-only
  shortcuts `realm_id` / `actor` / `actor_id`
- forbids `after` + `before` together (returns `invalid_param`); spec
  defines them as an open interval `(after, before)`
- does not honor the spec `order=default|ascending|descending` enum
- does not honor the spec `filters` deepObject parameter

**Recommendation**:
- Drop the singular `realm_id` / `actor` / `actor_id` shortcuts (or move
  them to docs as "legacy aliases"). Spec only knows `realms[]` / `actors[]`.
- Accept `(after, before)` together (spec §3.3 open-interval semantics).
- Implement `order` enum.
- Decide whether `filters` deepObject is in scope. If yes, implement; if no,
  remove from the spec or move to `cx.events.query_post` (POST body).

---

## 4. Endpoints in soland, **not in spec** — recommendations

Operation IDs prefixed `cx.extension.soland.*` are explicit deployment-local
extensions; the others are silent (no operation_id registered) and need a
classification decision.

### 4.1 Account lifecycle (8 endpoints, all soland-only)

| Path | Method | operation_id | Recommendation |
|---|---|---|---|
| `/api/v1/account/register` | POST | `cx.extension.soland.account.register` | **Promote to spec.** Account self-registration is a fundamental capability and ought to be a canonical operation `cx.account.register` (or marked explicitly as out-of-scope if the spec stance is "account creation is via the external auth provider"). |
| `/api/v1/account/me` | GET | `cx.extension.soland.account.me` | **Promote to spec.** Reading the authenticated principal's profile is universal. Suggest `cx.account.get_self`. |
| `/api/v1/account/handle` | POST | `cx.extension.soland.account.claim_handle` | **Promote.** Handle claim is a spec-level concept (directory uses handles). `cx.account.claim_handle`. |
| `/api/v1/account/handle/transfer` | POST | `cx.extension.soland.account.transfer_handle` | **Promote.** Handle portability is a Contrix principle. |
| `/api/v1/account/profile` | POST | `cx.extension.soland.account.update_profile` | **Promote.** Profile update is universal. |
| `/api/v1/account/export` | POST | `cx.extension.soland.account.export` | **Promote.** GDPR-style data export is non-negotiable for a federated service. |
| `/api/v1/account/erase` | POST | `cx.extension.soland.account.erase` | **Promote.** Right-to-be-forgotten. Pair with `erasure_propagation_window_ms` already in config. |
| `/api/v1/account/{did}/principal-space` | GET | `cx.extension.soland.account.principal_space` | **Promote or supersede.** The "principal space" pattern (per-actor private realm) is a Contrix concept. Either add to spec or switch callers to `cx.projection.spaces?actors=...`. |

### 4.2 Auth (4 endpoints, all soland-only)

| Path | Method | operation_id | Recommendation |
|---|---|---|---|
| `/api/v1/auth/bridge/describe` | GET | none | **Add operation_id + promote.** Suggest `cx.auth.bridge_describe`. Spec already defines `auth/account/session-grants` etc., so an auth-bridge describe fits. |
| `/api/v1/auth/dev-login` | POST | `cx.auth.dev_login` | **Keep as extension, document.** Should be gated by `development_mode=true` only. Add a `cx.extension.soland.auth.dev_login` operation_id (drop the canonical `cx.auth.*` prefix — it's deployment-only). |
| `/api/v1/auth/session-grant/exchange` | POST | `cx.extension.soland.auth.exchange_session_grant` | **Promote to spec** as `cx.auth.exchange_session_grant`. The session-grant flow is the binding between coauth and the core service; spec should cover it. Spec currently has `auth/account/session-grants` (creation); the soland `exchange` step is the natural complement. |
| `/api/v1/auth/logout` | POST | `cx.extension.soland.auth.logout` | **Promote.** Logout is universal; `cx.auth.logout`. |

### 4.3 Contacts (3 endpoints, all soland-only)

| Path | Method | operation_id | Recommendation |
|---|---|---|---|
| `/api/v1/contacts` | GET | `cx.extension.soland.contacts.list` | **Promote.** Contacts are a Contrix-level concept (used by directory/discovery). `cx.contacts.list`. |
| `/api/v1/contacts/request` | POST | `cx.extension.soland.contacts.request` | **Promote.** `cx.contacts.request`. |
| `/api/v1/contacts/respond` | POST | `cx.extension.soland.contacts.respond` | **Promote.** `cx.contacts.respond`. |

### 4.4 Notifications (2 endpoints)

| Path | Method | operation_id | Recommendation |
|---|---|---|---|
| `/api/v1/notifications` | GET | none | **Decide: promote OR move to index/inbox.** Spec exposes `push/notify` (server → bridge) but no client-side notification inbox. Either add `cx.notifications.list` to spec, or migrate the UI to `cx.push.*` + index-side aggregation. |
| `/api/v1/notifications/mark-all-read` | POST | none | Same — if the notifications inbox is promoted, add `cx.notifications.mark_all_read`. |

### 4.5 Devices (4 endpoints)

| Path | Method | operation_id | Recommendation |
|---|---|---|---|
| `/api/v1/devices` | GET | `cx.devices.list` | **Promote.** Spec already has `keys/{upload,query,claim}` and `admin/devices/{device_id}/revoke`; a self-listing of one's own devices is the missing piece. Add `cx.devices.list` to spec. |
| `/api/v1/devices/pairing-challenge` | POST | `cx.extension.soland.devices.pairing_challenge` | **Reconcile with spec `auth/account/device-pair`.** Spec defines a single endpoint; soland splits into challenge + authorize. Either change soland to one-shot, or change spec to two-shot. Recommend spec adopts the soland two-step flow (challenge issuance + later authorization is more secure). |
| `/api/v1/devices/authorize-pairing` | POST | `cx.extension.soland.devices.authorize_pairing` | Same as above — second half of the pairing flow. |
| `/api/v1/devices/{device_id}/revoke` | POST | `cx.devices.revoke` | **Path mismatch with spec.** Spec defines `admin/devices/{device_id}/revoke` (admin-only). Soland's path is end-user-driven self-revoke. Both are useful — add `cx.devices.revoke_self` (path `/devices/{device_id}/revoke`) to spec, and keep the admin variant separate. |

### 4.6 Keys (1 extra)

| Path | Method | operation_id | Recommendation |
|---|---|---|---|
| `/api/v1/keys/backups/describe` | GET | none | **Add operation_id + promote.** Suggest `cx.keys.backups.describe`. Matches the "every aggregate has a describe" pattern. |
| `/api/v1/identity/webvh/register` | POST | none | **Switch to spec `identity/submit-did-operation`** if functionally equivalent, OR promote as `cx.identity.webvh.register` if it's the embedded-WebVH-provider-specific endpoint. Likely the latter — keep but rename to `cx.extension.soland.identity.webvh.register`. |

### 4.7 Sync helpers (3 endpoints)

| Path | Method | operation_id | Recommendation |
|---|---|---|---|
| `/api/v1/sync/typing` | POST | `cx.extension.soland.sync.typing` | **Promote.** Typing indicators are a baseline messaging feature. Add `cx.sync.typing` (or model as ephemeral event via `cx.events.submit`). |
| `/api/v1/sync/backfill/gap` | GET | `cx.extension.soland.sync.backfill_gap` | **Keep as extension OR replace.** If `cx.events.query` with `before=` cursors covers the same use case, switch callers and delete. If not, document the gap-specific semantics and promote. |
| `/api/v1/sync/snapshot-chunk` | GET | `cx.extension.soland.sync.get_snapshot_chunk` | **Promote.** Snapshot v2 is a spec concept (the `merkle_root` / `chunk_count` fields are described in `cx.snapshot.head`); chunk retrieval is the natural follow-up. Add `cx.snapshot.get_chunk`. |

### 4.8 Spaces (4 endpoints)

| Path | Method | operation_id | Recommendation |
|---|---|---|---|
| `/api/v1/spaces/{space_id}` | GET | `cx.extension.soland.spaces.get` | **Reconcile.** Spec exposes space data via `cx.projection.spaces?realms={id}`. A direct `GET /spaces/{id}` is more ergonomic. Either promote (`cx.spaces.get`) or migrate callers to the projection query. |
| `/api/v1/spaces/{space_id}/export` | GET | `cx.extension.soland.spaces.export` | **Keep as extension, document.** Full event-log + projection dump is operator/debug; rarely useful as a federated operation. Acceptable as a soland extension. |
| `/api/v1/read-markers` | POST/GET | none | **Promote.** Read markers are a fundamental client UX primitive. Add `cx.read_markers.{set,get}` to spec. Or, if the policy is "read markers ride on `cx.events.submit` with kind `cx.read_marker.set`", document that and remove the dedicated endpoint. |
| `/api/v1/receipts/read` | POST | none | **Reconcile with `cx.events.submit`.** Read receipts are typically an event kind. If so, this endpoint is redundant — migrate callers and delete. |

### 4.9 Projection (1 extra)

| Path | Method | operation_id | Recommendation |
|---|---|---|---|
| `/api/v1/projection/space-containers` | GET | `cx.extension.soland.projection.space_containers_legacy` | **Delete after sunset.** Operation ID literally says `_legacy`. Confirm no clients still use it, then remove. |

### 4.10 Index (9 endpoints)

The entire `/index/*` family is soland-only.

| Path | Method | operation_id | Recommendation |
|---|---|---|---|
| `/api/v1/index/describe` | GET | `cx.extension.soland.index.describe` | **Keep as extension.** The "index profile" is a soland implementation detail (reducer state). |
| `/api/v1/index/object` | GET | none | **Add operation_id; classify as extension** (`cx.extension.soland.index.object`). |
| `/api/v1/index/thread` | GET | none | Same — `cx.extension.soland.index.thread`. |
| `/api/v1/index/notifications` | GET | none | Overlaps with §4.4 `/notifications`. Pick one. |
| `/api/v1/index/inbox` | GET | none | **Add operation_id; promote IF the inbox is a stable concept**, else extension. |
| `/api/v1/index/search` | POST | none | **Promote.** Search is a baseline expectation. `cx.index.search` or `cx.search.query`. |
| `/api/v1/index/space-hierarchy` | GET | none | **Add operation_id.** Likely deployment-local — extension. |
| `/api/v1/index/query` | POST | `cx.extension.soland.index.query` | **Keep as extension.** Generic projection-index query is highly implementation-specific. |
| `/api/v1/index/debug/reducer` | GET | `cx.extension.soland.index.debug_reducer` | **Keep as extension; gate behind dev-mode flag.** This is an operator debug surface and should not be reachable in production. |

### 4.11 Realms (4 endpoints)

| Path | Method | operation_id | Recommendation |
|---|---|---|---|
| `/api/v1/realms/{realm_id}/links` | GET / POST | `cx.realms.links.list` / `cx.realms.links.create` | **Promote.** Realm-link primitives are spec-level — they're driven by `cx.realm.link` Moves (per the comments). Add the HTTP binding to spec. |
| `/api/v1/realms/{realm_id}/links/{target_realm_id}` | DELETE | `cx.realms.links.delete` | **Promote** alongside the above. |
| `/api/v1/realms/{realm_id}/effective-policy` | GET | `cx.realms.effective_policy.get` | **Promote.** "Effective policy after walking inheritance" is a spec concept (realm-policy inheritance is normative). |

### 4.12 Realm Policy Server (3 endpoints)

| Path | Method | operation_id | Recommendation |
|---|---|---|---|
| `/api/v1/realms/{realm_id}/policy-server` | GET | `cx.realms.policy_server.get` | **Promote.** Policy server config is a spec-level Move (`cx.realm.policy_server`). |
| same | PUT | `cx.realms.policy_server.put` | **Promote.** |
| same | DELETE | `cx.realms.policy_server.delete` | **Promote.** |

### 4.13 Federation (7 endpoints)

| Path | Method | operation_id | Recommendation |
|---|---|---|---|
| `/api/v1/federation/transactions/{txn_id}` | PUT | `cx.extension.soland.federation.transaction` | **Decide.** Federation transaction submit is a spec-level primitive. Either promote to `cx.federation.submit_transaction` or keep as a soland-side implementation detail (federation transport-binding may legitimately be deployment-specific). |
| `/api/v1/federation/push-operations` | POST | `cx.extension.soland.federation.push_operations` | **Reconcile with cross-server transport.** This duplicates whatever the spec's `/contrix/v1/` (federated) prefix should expose. The spec only has `/contrix/v1/ice-config` and `/contrix/v1/check`; if federation push is in scope for the federated transport spec, define it there. |
| `/api/v1/federation/pull-operations` | GET | `cx.extension.soland.federation.pull_operations` | Same — federation pull belongs in the federated transport binding. |
| `/api/v1/federation/space-members` | GET | `cx.extension.soland.federation.space_members` | **Reconcile with `cx.projection.spaces`.** Probably an extension forever, but document. |
| `/api/v1/federation/verify-actor` | POST | `cx.extension.soland.federation.verify_actor` | Likely a soland implementation detail; **keep as extension**. |
| `/api/v1/federation/anchors` | GET / POST | none | **Add operation_id.** Anchor exchange between federated servers is a spec-level primitive (witness anchors). Promote to `cx.federation.anchors.{pull,push}` or move to `/contrix/v1/anchors/...`. |

### 4.14 Authz (3 extras)

| Path | Method | operation_id | Recommendation |
|---|---|---|---|
| `/api/v1/authz/describe` | GET | none | **Add operation_id + promote.** Every other aggregate has a `describe`. `cx.authz.describe`. |
| `/api/v1/authz/grants` | POST | none | **Promote.** Grant creation is the inverse of `cx.authz.get_effective_grants`. `cx.authz.create_grant`. |
| `/api/v1/authz/grants/{grant_id}` | DELETE | none | **Promote.** `cx.authz.revoke_grant`. |

### 4.15 Policy CRUD (6 endpoints; spec only defines `/policy/check`)

| Path | Method | operation_id | Recommendation |
|---|---|---|---|
| `/api/v1/policies` | GET | `cx.extension.soland.policies.list` | **Promote.** Policy storage is a baseline server feature. `cx.policy.list`. |
| `/api/v1/policies/{policy_id}` | GET | `cx.extension.soland.policies.get` | **Promote.** `cx.policy.get`. |
| `/api/v1/policies` | POST | `cx.extension.soland.policies.upsert` | **Promote.** `cx.policy.upsert`. |
| `/api/v1/policies/{policy_id}` | PATCH | none | **Decide.** PATCH is unusual for the rest of the spec (which uses POST/PUT). Either drop PATCH and route through POST/PUT, or add operation_id + promote. |
| `/api/v1/policies/{policy_id}` | DELETE | `cx.extension.soland.policies.delete` | **Promote.** `cx.policy.delete`. |
| `/api/v1/policies/describe` | GET | none | **Add operation_id + promote.** `cx.policy.describe`. |

### 4.16 Push extras (4 endpoints)

| Path | Method | operation_id | Recommendation |
|---|---|---|---|
| `/api/v1/push/rules` | GET / POST | `cx.extension.soland.push.rules` / none | **Promote.** Push rules are the standard Matrix/Contrix client-config surface. Add `cx.push.rules.{list,upsert}` to spec. |
| `/api/v1/push/rules/{rule_id}` | DELETE | none | **Promote.** `cx.push.rules.delete`. |
| `/api/v1/push/outbound/bridge/cache/export` | GET | `cx.extension.soland.push.outbound_bridge_cache_export` | **Keep as extension.** Bridge cache snapshots are a soland-side operator/migration concern. |
| `/api/v1/push/outbound/bridge/cache/import` | POST | `cx.extension.soland.push.outbound_bridge_cache_import` | **Keep as extension.** Companion to the export above. |

### 4.17 WebRTC signaling (4 endpoints)

| Path | Method | operation_id | Recommendation |
|---|---|---|---|
| `/api/v1/webrtc/sessions` | POST | `cx.extension.soland.webrtc.create_session` | **Promote** alongside `cx.media.ice_config` (already in spec). The full set of voice/video signaling endpoints belongs in the canonical spec since clients are interoperable. Suggest `cx.media.create_session`. |
| `/api/v1/webrtc/sessions/{session_id}/signals` | POST | `cx.extension.soland.webrtc.send_signal` | **Promote.** `cx.media.send_signal`. |
| `/api/v1/webrtc/sessions/{session_id}/signals` | GET | none | **Add operation_id + promote.** `cx.media.poll_signals`. |
| `/api/v1/webrtc/sessions/{session_id}` | DELETE | `cx.extension.soland.webrtc.close_session` | **Promote.** `cx.media.close_session`. |

### 4.18 Admin (`/api/v1/admin/*`) — 14 endpoints

Spec defines only 4 admin endpoints (`server/status`, `accounts/{id}/status`,
`devices/{id}/revoke`, `moderation/queue`); soland has none of those four and
12 different ones (the `cx.extension.soland.admin.*` snapshot family) plus
`/admin/cells/*`.

| Path | Method | operation_id | Recommendation |
|---|---|---|---|
| `/api/v1/admin/{resource}` (catch-all) | GET | (per resource) | The catch-all router with 12 named resources (`actors`, `spaces`, `devices`, `capabilities`, `federation`, `applets`, `agents`, `reports`, `invite-tokens`, `audit`, `policy`, `media`) is **a soland admin-UI surface**, not a federated API. **Keep as extension.** Document that the spec's `/admin/server/status` etc. are a different (federated-identity-admin) surface that soland has not yet implemented. |
| `/api/v1/admin/cells` | GET | none | **Keep as extension** (operator debug for cell-family state). Add `cx.extension.soland.admin.cells.list`. |
| `/api/v1/admin/cells/{cell_id}` | GET | none | **Keep as extension.** Add `cx.extension.soland.admin.cells.get`. |

**Action item for spec coverage**: implement the four spec admin endpoints
(`/admin/server/status`, `/admin/accounts/{id}/status`,
`/admin/devices/{id}/revoke`, `/admin/moderation/queue`). They're missing
from soland — see §6.

### 4.19 Admin infra (`/api/admin/v1/*`) — 14 endpoints

Different prefix on purpose — these are **operator-only** infrastructure
ops over the anchor DAG, bottom-cell repair, multisig partial signatures,
GC candidates, and delivery-binding policy. They are deployment-internal and
should **never** be federated.

**Recommendation**: leave them out of the federated spec entirely. Add an
internal-operator-API document under `contrix-spec/spec/v1/zh/operations/`
(or keep this strictly in soland's deployment guide). All 14 paths listed
below stay as soland-only:

```
/api/admin/v1/spaces/{space_id}/anchorer                       GET
/api/admin/v1/spaces/{space_id}/anchorer/reconfigure           POST
/api/admin/v1/spaces/{space_id}/anchorer/rotate-signing-key    POST
/api/admin/v1/spaces/{space_id}/bottom                         GET
/api/admin/v1/bottom                                           GET
/api/admin/v1/spaces/{space_id}/bottom/{cell_id}/repair        POST
/api/admin/v1/spaces/{space_id}/anchor-dag                     GET
/api/admin/v1/spaces/{space_id}/anchor-dag/compact             POST
/api/admin/v1/spaces/{space_id}/anchor-dag/prune               POST
/api/admin/v1/spaces/{space_id}/multisig/pending               GET
/api/admin/v1/spaces/{space_id}/multisig/{anchor_id}/partial   POST
/api/admin/v1/spaces/{space_id}/gc-candidates                  GET
/api/admin/v1/realms/{realm_id}/delivery-binding-policy        GET
/api/admin/v1/spaces/{space_id}/delivery-binding-policy        GET  (410 Gone tombstone)
```

### 4.20 MLS extras (1 endpoint)

| Path | Method | operation_id | Recommendation |
|---|---|---|---|
| `/api/v1/keys/keypackages/welcomes/pending` | GET | `cx.extension.soland.mls.welcomes.pending` | **Promote.** Draining the MLS Welcome queue is the natural complement to spec's `cx.keys.keypackages.claim`. Add `cx.keys.keypackages.welcomes.pending` to spec. |

**Also missing in soland** (from §6): spec's `keys/keypackages/consume` and
`keys/keypackages/revoke`.

### 4.21 Extensions / Applet integration (core side; 9 endpoints)

These are soland's **core-server-side** of the applet boundary — not to be
confused with the spec's `/applet/*` surface (which is the **applet's**
side; see §6).

| Path | Method | operation_id | Recommendation |
|---|---|---|---|
| `/api/v1/extensions/manifests/verify` | POST | none | **Promote.** Manifest verification by the core is a spec-level operation. Add `cx.extensions.manifests.verify` to spec. |
| `/api/v1/extensions/bots` | POST | none | **Promote.** Bot/ghost actor registration. `cx.extensions.bots.register`. |
| `/api/v1/extensions/bots` | GET | none | **Promote.** `cx.extensions.bots.list`. |
| `/api/v1/extensions/bots/{did}` | DELETE | none | **Promote.** `cx.extensions.bots.revoke`. |
| `/api/v1/extensions/tsp/transports` | POST / GET | none | **Promote.** TSP transport declaration is a Contrix concept (Trust Spanning Protocol). Add `cx.extensions.tsp.transports.{declare,list}`. |
| `/api/v1/extensions/tsp/routes` | POST / GET | none | **Promote.** `cx.extensions.tsp.routes.{establish,list}`. |
| `/api/v1/extensions/tsp/audit` | GET | none | **Promote.** `cx.extensions.tsp.audit.get`. |

### 4.22 Conformance test helpers (6 endpoints)

| Path | Method | operation_id | Recommendation |
|---|---|---|---|
| `/api/v1/conformance/encode` | POST | none | **Gate by feature flag in production.** Either compile out in release builds, or expose only under `development_mode=true`. If the test harness needs them in CI, that's fine, but they shouldn't be reachable on a public deployment. Operation IDs could be `cx.conformance.{encode,sign,hlc_merge,cursor,envelope,redact}` under a separate "conformance test profile" in the spec. |
| `/api/v1/conformance/sign` | POST | none | Same. |
| `/api/v1/conformance/hlc-merge` | POST | none | Same. |
| `/api/v1/conformance/cursor` | POST | none | Same. |
| `/api/v1/conformance/envelope` | POST | none | Same. |
| `/api/v1/conformance/redact` | POST | none | Same. |

---

## 5. `/contrix/v1/*` (federated/cross-server) endpoints

| Path | Method | Status |
|---|---|---|
| `/contrix/v1/check` | POST | **Not in spec.** Soland alias for `/api/v1/policy/check`. Either delete (clients should use `/api/v1/policy/check`) or add to spec as the federated transport variant. |
| `/contrix/v1/ice-config` | POST | In spec, conforming. |

**Recommendation**: The `/contrix/v1/*` prefix is reserved by spec for
federated/inter-server transport. Soland's `/contrix/v1/check` is the
**same handler as `/api/v1/policy/check`** (see
`src/routing/access/policy.rs:54`). Either:
- (a) drop the alias and require all callers to use `/api/v1/policy/check`; or
- (b) document in spec that `cx.policy.check` is exposed at both
  `/api/v1/policy/check` (client-facing) **and** `/contrix/v1/check`
  (federated transport). Option (b) is probably closer to what's intended.

---

## 6. Endpoints in spec **but not implemented** in soland

These are gaps in soland's coverage of the canonical spec. Recommended
priority: P0 = core data path, blocks federation; P1 = should be present
on a complete server; P2 = optional/applet-side.

| Spec path | Method | operation_id | Priority | Recommendation |
|---|---|---|---|---|
| `/events/query` | POST | `cx.events.query_post` | P0 | **Implement.** Body-based variant of `cx.events.query` for large filter payloads / deep object filters. The GET variant exists; just need to add a sibling POST that takes the same params from the body. |
| `/identity/submit-did-operation` | POST | `cx.identity.submit_did_operation` | P0 | **Implement.** Soland has `/identity/webvh/register` which is webvh-specific; the spec wants a method-neutral DID operation submitter. |
| `/directory/private-contact-discovery` | POST | `cx.directory.private_contact_discovery` | P1 | **Implement** if the deployment supports it, else explicitly stub with `not_implemented`. Privacy-preserving discovery is a flagship Contrix feature. |
| `/directory/announce` | POST | `cx.directory.announce` | P1 | **Implement.** Voluntary announcement of a realm to the directory. |
| `/directory/withdraw` | POST | `cx.directory.withdraw` | P1 | **Implement** alongside announce. |
| `/directory/subscribe` | POST | `cx.directory.subscribe` | P1 | **Implement.** Subscribe to directory updates (mirrors `cx.account.subscribe`). |
| `/blob/presign` | POST | `cx.blob.presign` | P1 | **Implement.** Presigned-URL upload bypasses the server for large uploads — needed for media-heavy clients. |
| `/device_messages` | POST | `cx.device_messages.send` | P0 | **Implement.** To-device messages are part of MLS/E2EE delivery; soland has none of this surface. |
| `/device_messages` | GET | `cx.device_messages.poll` | P0 | **Implement.** Companion polling/long-poll endpoint. |
| `/keys/keypackages/consume` | POST | `cx.keys.keypackages.consume` | P0 | **Implement.** MLS KeyPackage lifecycle requires consume. Without it, federated MLS sessions can't enforce one-shot semantics. |
| `/keys/keypackages/revoke` | POST | `cx.keys.keypackages.revoke` | P0 | **Implement.** Same lifecycle gap. |
| `/applet/ping` | GET | `cx.applet.ping` | N/A | **N/A for soland.** This is the **applet's** API for the core service to call into. Not soland's responsibility unless soland also bundles an applet. |
| `/applet/describe` | GET | `cx.applet.describe` | N/A | Same. |
| `/applet/transactions` | POST | `cx.applet.transaction` | N/A | Same. |
| `/applet/actors/{actor_id}` | GET | `cx.applet.query_actor` | N/A | Same. |
| `/applet/realms/{realm_id_or_alias}` | GET | `cx.applet.query_space` | N/A | Same. |
| `/applet/protocols/{protocol}` | GET | `cx.applet.protocol_metadata` | N/A | Same. |
| `/applet/third_party/users` | GET | `cx.applet.third_party_users` | N/A | Same. |
| `/applet/third_party/locations` | GET | `cx.applet.third_party_locations` | N/A | Same. |
| `/auth/account/session-grants` | POST | `cx.auth.account.session_grants` | P1 | **Implement** (or reconcile with soland's `/auth/session-grant/exchange`). Spec defines this as the canonical session-grant minting endpoint. |
| `/auth/account/device-pair` | POST | `cx.auth.account.device_pair` | P1 | **Reconcile** with soland's two-step `pairing-challenge` + `authorize-pairing`. Either implement the spec one-shot or update spec to the two-shot. |
| `/auth/account/oidc/callback` | POST | `cx.auth.account.oidc_callback` | P1 | **Implement** if OIDC bootstrap is in scope for soland. Currently soland delegates OIDC to coauth (external) and uses session-grant exchange. |
| `/admin/server/status` | GET | `cx.admin.server.status` | P1 | **Implement.** Liveness/readiness for operators. |
| `/admin/accounts/{account_id}/status` | POST | `cx.admin.accounts.set_status` | P1 | **Implement.** Account-level moderation status. |
| `/admin/devices/{device_id}/revoke` | POST | `cx.admin.devices.revoke` | P1 | **Implement** alongside soland's self-revoke at `/devices/{device_id}/revoke`. The spec admin version is operator-driven (different auth). |
| `/admin/moderation/queue` | GET | `cx.admin.moderation.queue` | P1 | **Implement.** Operator-facing moderation queue. |

---

## 7. Summary Recommendations (prioritized)

### Spec changes to propose

1. **Promote ~25 soland-only endpoints to the canonical spec** under the
   `cx.*` namespace (account lifecycle, contacts, push rules, realm links,
   policy-server, snapshot chunks, WebRTC signaling, extensions/applet
   core-side, authz CRUD, policy CRUD, MLS welcomes/pending, devices/list,
   devices/self-revoke).
2. **Add `cx.events.query_post`** (POST /events/query) to soland to match spec.
3. **Rename MIMI path param `room_id` → `flow_id` in soland** (4 endpoints).
4. **Reconcile auth bootstrap**: spec's `auth/account/{session-grants,
   device-pair, oidc/callback}` vs soland's `auth/{dev-login, session-grant/
   exchange, logout, bridge/describe}` + `devices/{pairing-challenge,
   authorize-pairing}`. Pick one shape and implement on both sides.
5. **Mark soland's `/api/admin/v1/*` (anchor/DAG/multisig/bottom) as
   operator-only**; document outside the federated spec.
6. **Decide on `/conformance/*`** — gate behind dev-mode OR add a
   `cx.conformance.*` profile to the spec for test-time interop.

### Soland code changes to do

1. **Add `POST /api/v1/events/query`** (`cx.events.query_post`).
2. **Implement `/device_messages` POST/GET** (`cx.device_messages.{send,poll}`).
3. **Implement `/keys/keypackages/{consume,revoke}`** for MLS lifecycle.
4. **Implement `/identity/submit-did-operation`** (method-neutral DID submit).
5. **Implement `/blob/presign`** for large-upload offload.
6. **Implement `/directory/{announce,withdraw,subscribe,private-contact-discovery}`** (or return `not_implemented` stubs documented as such).
7. **Implement the 4 spec admin endpoints** (`/admin/server/status`,
   `/admin/accounts/{id}/status`, `/admin/devices/{id}/revoke`,
   `/admin/moderation/queue`).
8. **Fix `GET /events` parameter conformance**: drop `realm_id`/`actor`
   singular shortcuts (or alias-document), accept `(after, before)`
   simultaneously, implement `order=` enum, implement `filters=` deepObject
   (or push it into the POST body).
9. **Rename MIMI `{room_id}` → `{flow_id}`** in `src/routing/interop/mimi.rs`.
10. **Delete `/contrix/v1/check` alias** OR document it in spec.
11. **Delete `/api/v1/projection/space-containers`** after confirming no
    callers — its operation_id is literally `*_legacy`.
12. **Decide on `/api/v1/notifications` vs `/api/v1/index/notifications`** —
    pick one path.
13. **Decide on `/api/v1/receipts/read` vs an event-kind-based receipt** —
    consolidate.

### Items to leave as soland extensions

- `/api/admin/v1/*` (14 endpoints): operator-only anchor/multisig/bottom
  infrastructure. Keep out of spec.
- `/api/v1/admin/{resource}` snapshot family (12 named resources): soland
  admin-UI backend. Keep `cx.extension.soland.admin.*` namespace.
- `/api/v1/sync/snapshot-chunk`, `/api/v1/push/outbound/bridge/cache/*`,
  `/api/v1/auth/dev-login`, `/api/v1/index/debug/reducer`: deployment-local
  by design.

---

## 8. Coverage Statistics

```
Spec (path, method) pairs                          ~85
Spec pairs implemented in soland (literal match)   ~42   (49%)
Spec pairs implemented with param-name divergence    4
Spec pairs MISSING in soland                       ~21   (25%, mostly P0/P1)
Spec pairs marked N/A (applet-side, not core)        8

Soland (path, method) pairs under /api/v1         ~125
Soland pairs in spec                               ~46   (37%)
Soland pairs marked cx.extension.soland.*          ~36   (29%)
Soland pairs with NO operation_id (need triage)    ~43   (34%)

Soland pairs under /api/admin/v1                    14   (all out of spec, by design)
Soland pairs under /contrix/v1                       2   (1 in spec, 1 alias of in-spec)
```

The biggest single action item is **registering operation IDs for the ~43
soland endpoints that currently have none** (`#[endpoint(operation_id = ...)]`
or extend `SOLAND_EXTENSION_OPERATIONS`). Until every endpoint has an
operation_id, the conformance machinery (`KNOWN_ROUTES`, OpenAPI export,
client SDK generation) can't reason about them.
