# soland — Open Tasks

> Audit baseline: 2026-05-04. Reference implementation of `contrix-spec` v1
> (Salvo + Diesel/PostgreSQL + in-memory fallback). Completed work lives in
> `git log`; this file lists only **outstanding** tasks.
>
> Last refresh: 2026-05-07 — re-prioritized from an architecture-leverage
> angle. The previous P0..P4 partition mixed structural rewrites with single
> handler bug fixes; the new ordering is **chassis first**: every change in a
> later tier should be cheaper after the earlier tier lands.
>
> **Aggressive-mode rule for this branch**: backwards compatibility with
> previous wire shapes / handler signatures is **not** a constraint. Pick the
> right code, not the diff-minimal code.

---

## Tier 0 · Single source-of-truth for state

> Today `AppState` carries `persistence: Arc<dyn PersistenceStore>` **and**
> a remaining set of `Arc<Mutex<...>>` fields holding overlapping data.
> Every write path that hits both is a dual-write; every read path picks
> one arbitrarily. This is the structural root cause behind F2 and most of
> the "still in process memory, lost on restart" notes downstream.

> **Status (2026-05-07)** — Phases 1 + 2 of the trait expansion landed in
> this branch. `PersistenceStore` now covers **20 sub-stores**: original
> `accounts / sessions / contacts / space_meta / messages / blobs / devices
> / federation_transactions`, phase 1 `audit / moderation / federation_operations
> / push_devices / push_rules / presence / typing / push_bridge_cache /
> webrtc / policy_documents`, and phase 2 `schemas / identity / space_invites
> / events / projection_events / device_messages / device_keys / one_time_keys
> / key_backups`. `AppState` shrunk from ~32 mutex fields to **9 fields**
> total: `config / db / repo / persistence / hlc / projection / authz /
> spaces / did_resolver`, plus the four temporarily-retained
> `key_backup_restore_*` scaffold maps (T0-2c). 76/76 lib tests pass;
> integration tests build clean.

| # | Task | Files | Notes |
| --- | --- | --- | --- |
| **T0-1** ✅ phases 1+2 | ~~Expand `PersistenceStore` to cover every sub-store currently held as a mutex on `AppState`.~~ Done — 20 sub-stores in trait, all with Memory backend. | `src/persistence.rs`, `src/state.rs` | shipped 2026-05-07 |
| **T0-2** ✅ phases 1+2 | ~~Drop the per-state-surface mutex fields from `AppState` and route every handler through `state.persistence.<store>()`.~~ Done for everything except the four `key_backup_restore_*` scaffold maps; tracked separately as T0-2c. | `src/state.rs`, `src/routing/*`, `tests/http_api.rs` | shipped 2026-05-07 |
| **T0-2c** | Migrate `routing/key_backup_restore.rs` (~2K LOC, ~50 call sites) to use `state.persistence.key_backups()`. Today the file relies on raw `BTreeMap` semantics (`iter / retain / get_mut / values`) against the four mutex maps; the trait already exposes `put_ticket / get_ticket / put_executor_run / get_executor_run / put_approval_run / get_approval_run` plus snapshot helpers. The rewrite is mostly mechanical but cannot be batch-substituted because each call site needs slightly different shaping. After this lands, drop `key_backups / key_backup_restore_tickets / key_backup_restore_executor_runs / key_backup_restore_approval_runs` from `AppState` to reach the final 9-field shape. | `src/routing/key_backup_restore.rs`, `src/state.rs`, `src/persistence.rs` (may need `snapshot_tickets / snapshot_executor_runs / snapshot_approval_runs / delete_ticket / delete_executor_run / delete_approval_run` helpers) | follows phase-1 / phase-2 pattern |
| **T0-3** | Pg-backed implementation per sub-store (one migration + one `PgFooStore` per PR). Order by usage: federation_operations, audit, moderation, push, presence, schemas, events, identity, invites, key_backup, webrtc, policy, restore. Drop the `fallback: MemoryPersistenceStore` field on `PgPersistenceStore` once every sub-store is native. | `src/persistence.rs`, `migrations/*` | T0-2c first for `key_backups` |
| **T0-4** | Behavioral parity test suite: one shared test fn per sub-store, run twice (memory + Pg). Today every store is tested only against `MemoryFooStore` directly. | `src/persistence/tests.rs` | T0-1 done |

---

## Tier 1 · Pluggable reducer

> 28 of ~130 spec event kinds project today (~21%). The reducer is one giant
> match arm in `src/reducer.rs`; adding a kind means editing the same file.
> The architectural fix is a `Reducer` trait + registry so each new kind is a
> bounded per-file PR.

| # | Task | Files | Notes |
| --- | --- | --- | --- |
| **T1-1** | Define `trait ReducerKind { fn kind(&self) -> &'static str; fn evaluation_class(&self) -> EvaluationClass; fn project(&self, event: &CanonicalEvent, state: &mut ProjectionState) -> Result<(), ReducerError>; }`. `ProjectionState` becomes a holder of typed sub-states (`SpaceMetaState`, `SchemaRegistryState`, …). The dispatcher iterates a `BTreeMap<&'static str, Box<dyn ReducerKind>>`. | `src/reducer.rs` (split into `src/reducer/{mod,registry,kinds/*}.rs`) | unblocks A1-A19 |
| **T1-2** | Migrate the 28 already-projected kinds to the registry — one file per kind module. Existing tests stay green. | `src/reducer/kinds/*` | T1-1 first |
| **T1-3** | Land each remaining kind (A2..A19 in the old plan) as a single `kinds/<kind>.rs` PR. Kinds: `cx.space.*` (19 sub-kinds), `cx.schema.*`, `cx.morph.*`, `cx.view.*`, `cx.flow.*`, `cx.capability.*`, `cx.policy.*`, `cx.invite.*`, `cx.account.*`, `cx.account_data.*`, `cx.moderation.*`, `cx.audit.*`, `cx.identity.*`, `cx.did.proof`, `cx.session.grant`, `cx.device.*`, `cx.key.verification.*` (8), `cx.mls.*` (7), `cx.space_key.*` (3), `cx.member.state`, `cx.profile.*`, `cx.mimi.room_binding`, `cx.sovereign.did_policy`, `cx.organization.*`. | `src/reducer/kinds/*` | T1-1 + T1-2 first |
| **T1-4** | spec B-09 — `redact` reducer must preserve `actor_seq`. Currently `cleared` flattens attachments/mentions/relations; `hashes` must be cleared, not retained. | `src/reducer/kinds/redact.rs` | |

---

## Tier 2 · Wire format reset

> Drop the legacy field-name drift in one breaking pass — no shim, no alias.
> spec M-01..M-07 collapses to "delete the legacy names, regen tests".

| # | Task | Files | Notes |
| --- | --- | --- | --- |
| **T2-1** | spec M-01 — remove `event_type` entirely; keep only `event_kind`. Drop the dead `aad_ambiguous_kind` error. Drop the duplicate `event_type / input_event_type / canonical_event_type` triple on `ProjectionEventRecord`. | `src/wire.rs`, `src/state.rs::ProjectionEventRecord`, `src/reducer.rs`, all handlers, all tests | spec M-01 |
| **T2-2** | spec M-02..M-07 — unify `principal_id / subject / holder_did`, `session_key_pub / session_public_key`, `Proof.kind`, `read_marker.id` pattern. One name per concept; delete the others. | `src/wire.rs`, handlers | spec M-02..M-07 |
| **T2-3** ✅ | ~~every sync/directory response uses the `cx:space:` prefix~~ Done — all sync/directory responses already emit `cx:space:` (verified by grep). Removed the dead legacy-`space:` strip workaround in `src/routing/authz.rs:47-49` so the `authz.check` request resource string is forwarded verbatim per spec M-15. | grep + fix | |
| **T2-4** | Grant envelope shape and constraint schema aligned to v1.0 `grant-constraint.schema.json` — 8 family (`temporal / field_access / type_restriction / scope_limitation / delegation_control / quota / claim_based / confidentiality`) + `subtype`. Drop the legacy 14-name model and the `condition.when` string DSL. | `src/authz.rs`, `src/wire.rs`, spec mirror | B1 (old plan) |
| **T2-5** | spec B-10 — KeyPackage shape unified to `principal_id/device_id/keypackage_id/device_signature/expires_at`. | `src/routing/keys.rs`, wire | F-3 (old plan) |
| **T2-6** | spec B-11 — merge `secret_storage` and `key_backup` into `cx.schema.key_backup.v1` + `domain` enum; HKDF info per domain. | `src/routing/key_backup.rs`, wire | F-4 (old plan) |
| **T2-7** | spec B-22 — encrypted attachment `key_ref` switched to object form `{algorithm, group_state_ref}`; drop string `"mls_epoch:42"`. | `src/routing/blob.rs`, `src/wire.rs` | F-6 (old plan) |
| **T2-8** | spec B-14 — DIDs MUST NOT appear in push payload / TURN username / push `sender`. Replace with Space-scoped pairwise pseudonym or ephemeral token; add MUST_NOT conformance tests. | `src/routing/{push,webrtc,push_outbound}.rs` | F-1 (old plan) |
| **T2-9** | spec B-23 — blob metadata adds `space_id` association + download/GC checks. | `src/routing/blob.rs`, `migrations/*` | F-7 (old plan) |
| **T2-10** | spec B-12 — MLS GroupContext extension `cx_app_state_ref` allocated a private codepoint (0xF000–0xFFFF) and registered. | `contrix-spec/spec/v1/artifacts/`, `src/wire.rs` | F-5 (old plan) |

---

## Tier 3 · Authz / capability / policy unification

> After T2-4 lands the new constraint model, the rest of authz is a focused
> rewrite. Today `authz_check` and `policy_check` are independent and
> inconsistent; obligations are echoed not executed; revocation is a single
> bool.

| # | Task | Files | Notes |
| --- | --- | --- | --- |
| **T3-1** | Implement constraint family/subtype evaluators — temporal / field_access / type_restriction / scope_limitation / delegation_control / quota / claim_based / confidentiality (and historical `rate_limiting / approval_workflow / encryption_requirement / edit_window / device_session` as subtypes). | `src/authz.rs::evaluate_constraint` | B2 |
| **T3-2** | Implement every `condition.kind` case from the v1.0 schema. Currently fail-open. | `src/authz.rs` | B3 |
| **T3-3** | Use `evaluation_class: enum("stateless","grant_local","space_state","external")` from constraint metadata; bucket caches by class. | `src/authz.rs`, spec schema | B4 |
| **T3-4** | Feed reducer `cx.capability.*` (T1-3) and `cx.invite.*` (T1-3) projections into `effective_grants()`. Today only direct grants — no delegation/revocation chain. | `src/authz.rs`, `src/routing/authz.rs` | B6 |
| **T3-5** | Invite ↔ grant linkage — accept-invite issues a grant; revoke-invite revokes the dangling grant; audit linked. | `src/routing/{authz,invite}.rs` | B7 |
| **T3-6** | Merge `policy_check` and `authz_check`; one decision pipeline. Today they live in two route handlers with different inputs. | `src/routing/{authz,policy}.rs` | B9 |
| **T3-7** | Execute obligations — bind to reducer / write path / quarantine. Today they're echoed as JSON. | `src/routing/policy.rs` | B10 |
| **T3-8** | Revocation beyond a single `grant.revoked` bool — bulk / scope / time-window / CRL revocation; federation revocation fan-out (spec M-18). | `src/authz.rs` | B11 |
| **T3-9** | Decision-cache TTL by `evaluation_class` instead of hardcoded 5 min. | `src/authz.rs`, `src/state.rs` | B12 |
| **T3-10** | Capability lattice (auth_weight 11 levels) — currently flat boolean. Spec M-09 requires explicit causal_depth tie-break. | `src/authz.rs` | B8 |

---

## Tier 4 · Recovery / key-backup data model

> 46+ scaffold endpoints (`recovery/{discovery,readiness,live-snapshot,stack-bundle}`,
> `keys/backups/restore-state/*`, `keys/backups/restore-tickets/{ticket_id}/*`)
> all return `scaffold_*` placeholders. One data model unblocks the lot.

| # | Task | Files | Notes |
| --- | --- | --- | --- |
| **T4-1** | Land `RecoveryTicket / RestoreCheckpoint / RestoreApproval / RestoreExecutorRun / RestoreReceipt` as records on `PersistenceStore` (wired through Tier 0). State machine: `pending → approved → enqueued → running → materialized → completed/failed/canceled`. | `src/persistence.rs`, new `src/recovery.rs`, `migrations/*` | unblocks T4-2..T4-11 |
| **T4-2** | `keys/backups` PUT/GET/DELETE/LIST through T4-1 store; full schema validation (`cx.schema.key_backup.v1` from T2-6). | `src/routing/key_backup.rs` | |
| **T4-3** | Restore-ticket lifecycle handlers: `describe / start / advance / resume / cancel / retry`. | `src/routing/key_backup_restore.rs` | |
| **T4-4** | Restore approvals: `approvals/status / approvals/submit` — real reviewer authorization + quorum + audit. | same | |
| **T4-5** | Restore executor: `executor/{status,enqueue,start,complete}` — persistent worker lease/heartbeat + failure compensation. | same | |
| **T4-6** | Restore artifact endpoints: `result / receipt / bundle / activity / timeline / audit-feed / materialized-device-handoff` — drop synthetic dummy IDs. | same | |
| **T4-7** | Restore-state snapshots: `describe / export / import / durability / checkpoints` via T4-1 store + trust/freshness policy. | same | |
| **T4-8** | `recovery/discovery` real service discovery + DID-bound audience metadata. | `src/routing/recovery.rs` | |
| **T4-9** | `recovery/readiness` real storage / authz / policy / crypto health checks. | same | |
| **T4-10** | `recovery/live-snapshot` actor-scoped dashboard + pagination + privacy boundary. | same | |
| **T4-11** | `recovery/stack-bundle` assembled from real `recovery/contract-stack` output; remove inline path list. | same | |
| **T4-12** | spec M-28 — `did:plc degraded_mirror_only` 7-day hard limit needs grace/extension. | `src/routing/identity.rs` | |

---

## Tier 5 · Typed routing surface

> Q1 in the old plan; absorbs the full `_oapi.md` migration plan (deleted
> 2026-05-07). The job is to mirror palpo's typed-extractor pattern across
> soland's ~180 endpoints so each `#[endpoint]` produces a real OpenAPI
> operation with `parameters[]` + `requestBody` + typed `responses[]`,
> then delete the `SOLAND_EXTENSION_OPERATIONS` compatibility table that
> backfills untyped routes.
>
> **Foundation (Phase A) — landed**:
> `AuthArgs` extractor ([src/routing/extract.rs](src/routing/extract.rs)),
> `AppError + EndpointOutRegister` ([src/error.rs](src/error.rs)),
> `JsonResult<T> / EmptyResult / json_ok / empty_ok`
> ([src/result.rs](src/result.rs)), every wire struct derives
> `salvo::oapi::ToSchema` ([src/wire.rs](src/wire.rs)), salvo's
> `Json<T>` is Writer + ToSchema. SDK side: `SpaceSearchEntry` got
> `derive(ToSchema)` and the `salvo` feature was wired through the
> `contrix` crate.

### Per-domain conversion (B..L)

> **Progress: 30 / ~183 endpoints converted (B + C + D landed; E..L
> pending).** Each row is one PR. After Phase A lands these can run in
> parallel. The recipe:
>
> - `JsonBody<RequestT>` for POST/PUT bodies (every wire request type
>   already derives `ToSchema`).
> - `PathParam<String>` per `{space_id}` / `{member_did}` segment; multiple
>   args picked up by name.
> - `QueryParam<T, REQUIRED>` for query strings.
> - `aa: AuthArgs` for protected routes; call
>   `aa.authenticated_session(state, req)?`.
> - `JsonResult<ResponseT>` return.
> - Use `AppError::not_found / invalid_param / capability_denied`
>   convenience constructors; `AppError::new(code, msg).with_status(...)`
>   when the registry status needs override.
> - Helpers that previously rendered into `Response` get a
>   `Result<T, AppError>` twin (see `space::space_lifecycle_response`).
> - Each per-domain PR extends `tests/openapi_typed.rs` with the new
>   request/response type names.

| # | Phase | Domain | Endpoints | Files |
| --- | --- | --- | --- | --- |
| **T5-1.B** ✅ landed | B | describe (introspection) | 8 | `src/routing/describe.rs` |
| **T5-1.C** ✅ landed | C | auth + account + device-pairing | 10 (3+5+2) | `src/routing/{auth,account,device}.rs` |
| **T5-1.D** ✅ landed | D | space + message + reaction + read_marker | 12 (5+3+2+2) | `src/routing/{space,message,reaction,read_marker}.rs` |
| **T5-1.E** | E | entity + relation + view + schema | 16 | `src/routing/{entity,relation,view,schema}.rs` |
| **T5-1.F** | F | sync + events + repo | 23 | `src/routing/{sync,events,repo}.rs` |
| **T5-1.G** | G | directory + identity + index | 23 | `src/routing/{directory,identity,index}.rs` |
| **T5-1.H** | H | authz + policy + admin + audit | 13 | `src/routing/{authz,policy,admin,audit}.rs` |
| **T5-1.I** | I | keys + key_backup_restore | 34 | `src/routing/{keys,key_backup_restore}.rs` |
| **T5-1.J** | J | push + push_outbound + profile | 14 | `src/routing/{push,push_outbound,profile}.rs` |
| **T5-1.K** | K | federation + mimi + webrtc + blob + moderation + device_messages | 24 | `src/routing/{federation,mimi,webrtc,blob,moderation,device_messages}.rs` |
| **T5-1.L** | L | recovery + remaining mod.rs/lib.rs handlers | 6 | `src/routing/recovery.rs`, `src/routing/mod.rs`, `src/lib.rs` |

### Cleanup (Phase M — once every per-domain phase lands)

| # | Task | Files |
| --- | --- | --- |
| **T5-M-1** | Delete the `SOLAND_EXTENSION_OPERATIONS` table from `src/lib.rs`. Every operation_id, summary, request body, and response body now comes from `#[endpoint]` annotations. The OpenAPI test in `tests/http_api.rs` should now pass against `merge_router(&router)` alone. | `src/lib.rs`, `tests/http_api.rs` |
| **T5-M-2** | Delete `register_soland_specific_schemas` once `FacetName / ViewRenderer / FacetConstraint / IndexQueryRequest` are typed in `src/wire.rs` and reachable from `index_query`'s `JsonBody<IndexQueryRequest>`. | `src/lib.rs`, `src/wire.rs` |
| **T5-M-3** | Drop `crate::routing::util::{render_error, query_param, query_flag, query_list, bearer_token}` once every callsite has been replaced by typed extractors / `AppError::from_error_code(...)?`. | `src/routing/util.rs` |
| **T5-M-4** | Drop the `auth_or_render` / `authenticated_session` raw helpers in `src/routing/auth.rs` in favor of the new `AuthArgs` extractor. | `src/routing/auth.rs` |
| **T5-M-5** | Add a positive OpenAPI test that asserts e.g. `paths."/api/v1/messages/send".post.requestBody.content."application/json".schema.$ref == "#/components/schemas/SendMessageRequest"` for representative routes — locks in that real schemas are wired, not synthetic placeholders. | `tests/http_api.rs` |

### Per-endpoint template

```rust
// before
#[endpoint]
pub async fn send_message(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    let state = depot.obtain::<AppState>().expect("state injected");
    let Some(session) = auth_or_render(state, req, res) else { return; };
    let body: SendMessageRequest = match req.parse_json().await {
        Ok(body) => body,
        Err(_) => { render_error(res, BAD_REQUEST, "bad_json", "invalid send"); return; }
    };
    // …
    res.render(Json(SendMessageResponse { … }));
}

// after
#[endpoint(
    operation_id = "cx.messages.send",
    tags("messages"),
    summary = "Send a message to a Space",
)]
pub async fn send_message(
    aa: AuthArgs,
    depot: &mut Depot,
    body: JsonBody<SendMessageRequest>,
) -> JsonResult<SendMessageResponse> {
    let state = depot.obtain::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state)?;
    let body = body.into_inner();
    // … same validation + state writes, but using `?` against AppError …
    json_ok(SendMessageResponse { … })
}
```

### Risk register

| Risk | Mitigation |
| --- | --- |
| `derive(ToSchema)` on a wire type fails because of a custom `Deserialize` (e.g. an enum with `serde(untagged)`). | Implement `ToSchema` manually with `Object::with_type(BasicType::Object)` — palpo does this for `LoginType` / `ErrorKind`. |
| `JsonBody<T>` rejects a body the existing `req.parse_json::<T>().await.unwrap_or_default()` callsite tolerated. | `body.into_inner()` first; if it `is_default()`, re-parse the raw payload via `req.payload().await`. Same fallback as palpo. |
| Auth flow uses both bearer tokens **and** federation HTTP-message-signature; `AuthArgs` doesn't capture both. | Two extractors: `AuthArgs` (bearer) and `FederationAuthArgs` (signature header bundle). Each handler picks one. |
| Generated OpenAPI bloats from schema duplication. | salvo-oapi already deduplicates by component name; `install_contrix_oapi_namer()` short-mode keeps names compact. |
| `tests/http_api.rs::contrix_openapi_spec_contains_facet_projection_contracts` fails mid-migration because `SOLAND_EXTENSION_OPERATIONS` and the new typed entries collide on the same path. | `add_contract_operation` in `src/lib.rs` already skips entries whose (path, method) is already populated by a typed `#[endpoint]`. Keep the table until **every** route in the test list has been converted; delete it in T5-M-1. |

### Out of scope for Tier 5

- Per-handler **`instrument(span)`** observability — see T5-3 below (and Q5
  in the legacy plan).
- **Federation HTTP-message-signature** transcript — T6-F-1 (spec B-06).
- **Streaming response** types (e.g. `sync_subscribe`'s SSE) — they need a
  custom `Writer`/`EndpointOutRegister` impl rather than `Json<T>`. Note
  in the per-domain rows when encountered.
- The dev-only `dev_login` and `admin/{resource}` routes get converted too,
  but ship behind a `dev` Cargo feature per T7-10 / Sec-2.

### Other Tier 5 follow-up

| # | Task | Files | Notes |
| --- | --- | --- | --- |
| **T5-3** | Tracing — every handler entry `instrument(span)` carrying actor / space / event_kind. | `src/routing/*` | Q5 |

---

## Tier 6 · Federation / MIMI / directory / push subsystem completion

> Parallel after Tiers 0-2 land. Each row is one subsystem's worth of
> follow-up.

### Federation

| # | Task | Files | Notes |
| --- | --- | --- | --- |
| **T6-F-1** | spec B-06 — federation signature transcript fully on RFC 9421 (`@method / @target-uri / @authority / content-digest / created / expires`); drop legacy field names. | `src/routing/federation.rs` | C1 |
| **T6-F-2** | `federation_push_operations` writes through to a persistent `federation_operations` table; idempotency key (spec M-20). | `src/routing/federation.rs`, `persistence.rs` | C2 |
| **T6-F-3** | `federation_pull_operations` reads from the persistent table with a cursor; survives restart. | same | C3 |
| **T6-F-4** | `federation_space_members` from reducer membership state (depends on T1-3 `cx.space.*`). | same | C4 |
| **T6-F-5** | `federation_verify_actor` validates signatures / DID document / key set; returns `validation_class` enum (spec M-19). | same | C5 |
| **T6-F-6** | Revocation fan-out TTL + retry policy (spec M-18). | same | C6 |

### MIMI

| # | Task | Files | Notes |
| --- | --- | --- | --- |
| **T6-M-1** | MIMI `room_update / notify / room_message` ingest into `cx.*` events instead of audit log; remove demo "alice" mapping. | `src/routing/mimi.rs` | C7 |
| **T6-M-2** | MIMI `consent_request / consent_update` via Tier-3 consent state machine + persistence. | same | C8 |
| **T6-M-3** | MIMI `key_material` issues / fetches a real KeyPackage (links to T1-3 `cx.mls.*`). | same | C9 |
| **T6-M-4** | MIMI `identifiers_query` via Tier-6-D directory; drop hardcoded alice. | same | C10 |
| **T6-M-5** | MIMI `report_abuse` / `proxy_download` route through Tier-0 moderation/blob stores. | same | C11 |
| **T6-M-6** | MIMI provider/protocol directory from config, not a static literal. | same | C12 |

### Directory / search / moderation

| # | Task | Files | Notes |
| --- | --- | --- | --- |
| **T6-D-1** | Tier-0 PgStore adds `actors / organizations / handles` tables + indexes; directory handlers read them. | `migrations/*`, `persistence.rs` | E1 |
| **T6-D-2** | `search_spaces` cursor + ranking + privacy/visibility filters. | `src/routing/directory.rs` | E2 |
| **T6-D-3** | Anti-enumeration: rate limits / consent / fuzzy matching. | same | E3 |
| **T6-D-4** | Moderation pipeline: `moderation_report` writes through T0/T4 + async review workflow + reducer T1-3 link. | `src/routing/moderation.rs` | E4 |
| **T6-D-5** | `moderation/report` SLA / status query (reporter-visible). | same | E5 |

### Push / device / crypto / privacy

| # | Task | Files | Notes |
| --- | --- | --- | --- |
| **T6-P-1** | `keys/upload / query / claim` via PgStore (Tier-0 wiring); revocation propagation linked with reducer T1-3 `cx.device.*`. | `src/routing/keys.rs`, `persistence.rs` | F-2 |
| **T6-P-2** ✅ snapshot store | ~~replace process-memory cache with persistent snapshot store~~ Done — `PgPushBridgeCacheStore` + migration `20260507000100_push_bridge_cache` landed; `OutboundPushBridgeCacheRecord` round-trips through Pg. Remaining: etag/freshness fields require extending the in-memory record first, then surfacing on the SQL row; fail-closed on contract drift still TODO in `push_outbound.rs`. | `src/routing/push_outbound.rs`, `src/persistence.rs` | F-8 |
| **T6-P-3** | `auth/session-grant/exchange` and `push/register-device` `TODO(session-grant)` bridge — coauth-backed introspection + audience binding + session-public-key proof verification. | `src/routing/{auth,push}.rs` | F-9 |
| **T6-P-4** | WebRTC sessions / signals persistence (after Tier 0); ICE config no longer returns an empty array. | `src/routing/webrtc.rs` | F-10 |
| **T6-P-5** | Profile/presence via Tier-0 presence store; presence/typing distinguish ephemeral vs durable channels. | `src/routing/profile.rs` | F-11 |

### Sync / state-resolution

| # | Task | Files | Notes |
| --- | --- | --- | --- |
| **T6-S-1** | `client_sync` actually maps `cx:cursor:` to reducer event sequence. | `src/routing/sync.rs` | S1 |
| **T6-S-2** | `snapshot-chunk` splits into deterministic multi-chunk. | same | S2 |
| **T6-S-3** | spec B-03 — history_visibility (`invited` / `restricted`) — three divergences unified through the reducer. | `src/reducer/*`, `src/routing/sync.rs` | S3 |
| **T6-S-4** | spec M-16 — formalize and validate `$ME` / `*` wildcard semantics in sync subscription. | `src/routing/sync.rs` | S5 |
| **T6-S-5** | spec M-09 / M-10 follow-up — 4 state-resolution conformance vectors (with spec). | tests + spec | S6 |
| **T6-S-6** | `index/debug/reducer` in-memory snapshot replaced with persistent projection. | `src/routing/index.rs` | S7 |

---

## Tier 7 · Operations & security audit

> Smaller, well-bounded items. Most are 1-2 hour PRs each.

| # | Task | Files | Notes |
| --- | --- | --- | --- |
| **T7-1** | Rate-limit single-process → shared store (Pg/Redis); restart no longer wipes counters. | `src/ratelimit.rs` | Q6 |
| **T7-2** | Tests split — `tests/http_api.rs` is one 5233-line / 42-test file. Carve into `tests/{auth,reducer,authz,federation,mimi,recovery,...}.rs` with shared `setup` in `tests/common/mod.rs`. | `tests/*` | Q7 |
| **T7-3** | End-to-end conformance — run spec `artifacts/fixtures/*` through `submit → reduce → query` round-trip as the conformance gate. | `tests/conformance.rs` (new) | Q8 |
| **T7-4** | `dev_login` / `admin/{resource}` and other dev-only paths gated behind a runtime hard guard (matching the SDK's "production" feature) instead of just `state.config.development_mode`. | `src/routing/{auth,admin}.rs` | Q9 |
| **T7-5** | Security audit — every `accept` branch on the `SERVERX_DEVELOPMENT_MODE=false` path goes through real proof verification; back this with negative conformance tests. | `tests/security.rs` (new) | Q10 |
| **T7-6** | CI — add `python ../contrix-spec/tools/artifact_pipeline.py check` (drift gate) wired up. (`cargo clippy -D warnings` and `cargo fmt --check` already in.) | `.github/workflows/*` | Q11 |
| **T7-7** | CORS handler validates that `SERVERX_CORS_ALLOW_ORIGIN` is a well-formed URL and is not `*` when `allow_credentials=true`. | `src/lib.rs::cors_handler_for_origin`, `src/config.rs` | Sec-3 |
| **T7-8** | Drop `unsafe { std::env::set_var(...) }` round-trip for `DATABASE_URL`. Pass URL through `AppState` / `Db::connect(&url)`. | `src/main.rs`, `src/db.rs` | Sec-6 |
| **T7-9** | Negative conformance test — every `dev-proof`/`alg=none` accept path returns 403 when `development_mode=false`. | `tests/security.rs` (new) | Sec-7 |
| **T7-10** | `dev_login` / `admin/*` either compiled out behind a `dev` Cargo feature or refuse to start with `development_mode=true` while binding `0.0.0.0:*`. | `src/routing/{admin,auth}.rs`, `src/lib.rs`, `Cargo.toml` | Sec-2 |
| **T7-11** | Surface knobs that aren't configurable — `SERVERX_REQUEST_BODY_LIMIT`, `SERVERX_BLOB_MAX_BYTES`, `SERVERX_RATE_LIMITER_*`, `SERVERX_TRACING_FORMAT`, `SERVERX_OTEL_ENDPOINT`. | `src/config.rs`, `src/main.rs`, `src/ratelimit.rs` | Cfg-1 |
| **T7-12** | `redact_database_url()` helper before logging; add `Debug` redaction for `AppConfig`. | `src/config.rs`, `src/main.rs` | Cfg-2 |
| **T7-13** | Validate `SERVERX_BLOB_ROOT` at startup — exists, writable, not system temp on production. | `src/config.rs` or `src/main.rs` | Cfg-3 |
| **T7-14** | `Dockerfile` `HEALTHCHECK` directive deferring to `/health`. | `Dockerfile` | Dep-2 |
| **T7-15** | `Dockerfile` blob-root chown + permission documentation. | `Dockerfile` | Dep-4 |
| **T7-16** | `docker-compose.yml` for local development (postgres + soland + adminer). | `docker-compose.yml` (new) | Dep-5 |
| **T7-17** | `/metrics` Prometheus endpoint — counters/histograms separate from tracing. | new module + `src/lib.rs` | Dep-6 |

---

## Open bugs (parallel-track CI gate)

| # | Task | Files | Notes |
| --- | --- | --- | --- |
| **B1** | **Integration-test hangs** — `account_contacts_and_space_lifecycle_workflow` and `admin_collection_surfaces_return_sodmin_shapes` (and ~8 more) hang under cargo test, even with `--test-threads=1`. Reproduce with `RUSTFLAGS="--cfg tokio_unstable" RUST_LOG=trace` + `tokio-console` or strip ratelimit / `wait_for_sync_token` middleware in a diff. | `tests/http_api.rs`, `src/ratelimit.rs`, `src/routing/mod.rs::wait_for_sync_token` | F5 (old plan) |
| **B2** ✅ | ~~`auth_keys_device_messages_and_blobs_work` panics on `legacy_field_push_body["error"]["message"]`~~ Fixed — assertion was reading the wrong key. `render_error` produces `error.error` (string) per `src/routing/util.rs:38-40`; both occurrences in `tests/http_api.rs:4084,4102` now read `["error"]["error"]`. | `tests/http_api.rs` | F6 (old plan) |

---

## Quick status (2026-05-07)

- **Code**: `src/` ~28K LOC; `tests/http_api.rs` 5.2K LOC / 42 tests.
- **Routes**: ~180 HTTP routes wired; many remain scaffold/echo (recovery,
  key-backup restore, push outbound bridge, MIMI, directory).
- **Persistence**: PgStore covers `accounts / sessions / devices /
  federation_transactions` natively; the rest falls back to MemoryStore —
  process restart wipes state. **Tier 0 phase 1 (2026-05-07) collapsed
  the dual-write for 11 surfaces** (audit / moderation / federation_ops /
  push_devices / push_rules / presence / typing / push_bridge_cache /
  webrtc / policy_documents). Phase 2 covers the remaining `events /
  projection_events / identity / invites / device_messages / device_keys
  / one_time_keys / key_backups / restore_* / blobs / schemas`.
- **Reducer**: 28 of 130 registered event kinds are projected (~21%). Tier 1
  is the architectural pivot here: until the giant match arm becomes a
  registry, each new kind drags the same file edit.
- **Authz**: implementation is behind current v1.0 constraint model
  (8 family + subtype). `condition.kind` cases incomplete; invite ↔ grant ↔
  policy not linked; obligations inert. Tier-3 follow-up after T2-4.
- **OpenAPI**: components seeded from contrix-sdk's
  `register_contrix_oapi_components`; routes discovered via
  `merge_router(&router)`. Per-handler typed extractors pending (Tier 5).
- **Spec drift**: live source is `contrix-spec/spec/v1/`; this file's prior
  B/M/Q labels are kept in the "Notes" column for cross-reference but no
  longer drive ordering.
- **CI**: 76/76 lib unit tests pass; 31 integration tests pass; B1/B2 above
  block green CI.

---

## Hard ordering constraints

- **Tier 0 first.** Every later tier writes through `PersistenceStore`; doing
  it after a half-migrated trait means re-doing each handler twice.
- **Tier 1 before T1-3 / T6-F-4 / T6-M-3.** Reducer registry must exist
  before per-kind work scales out.
- **Tier 2 (T2-4) before Tier 3.** New constraint model first, then build
  evaluators and obligations on top.
- **Tier 4 (T4-1) before T4-2..T4-11.** RecoveryTicket model first.
- **Tier 5 can run in parallel** with the rest as long as it doesn't fight
  Tier 1's reducer split.

---

## Out of scope (v1.x backlog)

- Reshape `auth_weight` 11-level scale into a `(governance_layer, authority_kind)`
  lattice (T3-10 is just a placeholder).
- spec M-38 / M-39 / M-40 — applet namespace, agent endpoint lifecycle, MIMI
  room_binding lifecycle.
- Multi-region / cross-service deployment (soland is a single-process
  reference).
- Full IANA codepoint application (T2-10 only assigns the private-use block).
