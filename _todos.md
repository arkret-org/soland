# soland — Principal Server Audit & TODO

> Audit date: 2026-05-04 (last touched 2026-05-05). Reference implementation of `contrix-spec` v1 (Salvo + Diesel/PostgreSQL + in-memory fallback).

## Round-1 progress (2026-05-05) — surgical wins landed

- [x] **A1a** `cx.relation.update` reducer now applies a patch-merge (`relation_kind / from / to / fields`, `null` removes a field) and emits `ProjectionEffect::RelationUpdated`. Prior dead match-arm in `apply()` is fixed.
- [x] **A1b** `apply_membership` now uses the canonical kind we already matched on instead of re-deriving from payload. `kick / ban / unban / knock` no longer collapse to `join` or `leave`. New `ProjectionState.banned_members` / `knocking_members` set; ban records membership removal + ban marker; unban lifts the marker without auto-rejoin; knock records intent without granting membership.
- [x] **A20** `ids::state_key_segment_encode` + `ids::state_key_compose` helpers (percent-encode `%` and `|` separator) with collision tests. Future composite state-key callers (capability, schema, policy projections) MUST use these instead of raw `format!("{a}|{b}")`.
- [x] **B5** `authz::highest_priority_decision` priority is now **deny → quarantine → require_review → allow** (`require_review` was previously masked by `allow`). Existing test renamed and the assertion flipped to lock the new behaviour.
- [x] **Q4** `artifacts::validate_embedded_artifacts() -> Result<(), ArtifactError>` runs from `main.rs` so a malformed bundled registry surfaces as a typed startup error rather than a first-request panic. Existing `parse_artifact` panic is now annotated as the unreachable safety net.
- [x] **build gate** Pre-existing build breaks discovered while verifying the above:
  - `contrix-rust-sdk` `crates/sdk/src/webrtc.rs:206` — `crate::Result<()>` did not resolve; switched to imported `Result` (matches the rest of the SDK).
  - `soland` `lib.rs` — bumped `#![recursion_limit = "512"]`; the recovery / key-backup / push-outbound scaffolds had grown past the default in `serde_json::json!` literals and were masking the rest of the build.
  - `soland` `handlers.rs` — `IntegrationDescribeResponse / IntegrationDependencyDescriptor / IntegrationSurfaceDescriptor` were used but unimported.
  - `soland` `handlers.rs::post_key_backup_restore_start` — `MutexGuard` over `state.key_backups` was held across `req.parse_json().await`, making the future `!Send`. Scoped the guard so the lock drops before the await.

`cargo check` is clean (one upstream `unused-qualifications` warning in `contrix-sdk`, not introduced here). **72 / 72 lib unit tests pass** — including new `state_key_*` tests and the renamed `require_review_and_quarantine_outrank_allow` authz test.

### Integration test status (`cargo test --test http_api`)

Independent of the changes above, the HTTP integration suite has pre-existing problems that were previously hidden by the broken build:

- ✅ At least 12 integration tests pass cleanly (e.g. `health_and_describe_work`, `events_describe_and_single_event_submit_work`, `device_pairing_challenge_and_authorization_surface_work`, `federation_*`, `identity_surface_works`, `framework_errors_use_contrix_error_envelope`, `broader_protocol_surface_returns_contract_shapes`, `contrix_openapi_spec_contains_facet_projection_contracts`, `directory_product_endpoints_return_demo_projection_shapes`, `device_messages_evicted_after_session_logout`, `configured_cors_allows_only_explicit_origin`).
- 🔴 **`account_contacts_and_space_lifecycle_workflow`** — hangs indefinitely (timed out at 60s, 180s, 600s). Confirmed reproducible with `src/reducer.rs` stashed back to `HEAD`, so **not caused by this round's changes**.
- 🔴 **`admin_collection_surfaces_return_sodmin_shapes`** — same: hangs indefinitely, also reproducible with reducer stashed.
- 🔴 **`auth_keys_device_messages_and_blobs_work`** — fails (assertion failure or render mismatch); does not touch any path modified this round (no `keys/backups/restore-start`, no membership reducer, no authz decision constraints).

The full 42-test integration run is unable to complete on this branch. Add a P0 task: **investigate the two hangs** (likely a missing `await` cancel, a busy-loop on a state lock, or an unbounded recursion through `app_from_state`/`service` builder when the same state is re-cloned 14× in one test) and the keys/blobs failure as separate items before claiming the suite is green again.

The remaining list below is unchanged in scope; everything else from the original audit is still pending.

## Round-2 progress (2026-05-05) — F1 partial: 5 domain modules + util extracted

`src/handlers.rs` (originally 19138 lines, 365 fn) was split into:

| File | Lines | Handlers | Notes |
| --- | --- | --- | --- |
| `src/handlers/mod.rs` | **17195** | rest | parent module; still holds the bulk of routes + the still-coupled helpers (`auth_or_render`, `authenticated_session`, `now`, `space_has_member`, `validate_*`-canonical-json/proof/operation, `append_audit_log`, `ingest_federation_operations`, `redaction_targets_from_operations`, `operation_is_visible`, blob helpers, …). Children pick them up via `super::name` or via the public `crate::handlers::*` re-exports (notably the `util` re-exports below). |
| `src/handlers/util.rs` | **243** | 0 | 19 mechanical helpers — `render_error`, `query_param/list/flag`, `bearer_token`, `sha256_hex`, `is_valid_sync_token`, `is_valid_sha256_digest/hex`, `is_valid_handle`, `normalize_handle`, `handle_for_did`, `is_valid_entity_type`, `is_supported_cx_entity_type`, `is_valid_discoverability`, `validate_did/device_id/space_id`, `is_json_integer`. All re-exported from `crate::handlers` so existing `super::render_error` / `super::query_param` references in sibling modules keep working unchanged. |
| `src/handlers/mimi.rs` | 619 | 12 | `mimi_protocol_directory / mimi_provider_directory / mimi_key_material / mimi_room_{update,notify,message} / mimi_group_info / mimi_consent_{request,update} / mimi_identifiers_query / mimi_report_abuse / mimi_proxy_download` plus 8 mimi-prefixed helpers. |
| `src/handlers/recovery.rs` | 387 | 5 | `recovery_contract_stack / get_recovery_{discovery,readiness,live_snapshot,stack_bundle}`. |
| `src/handlers/webrtc.rs` | 408 | 5 | `ice_config / create_webrtc_session / put_webrtc_signal / get_webrtc_signals / delete_webrtc_session` plus 5 webrtc helpers. |
| `src/handlers/moderation.rs` | 98 | 1 | `moderation_report`. |
| `src/handlers/federation.rs` | 396 | 5 | `federation_{transaction,push_operations,pull_operations,space_members,verify_actor}` plus 4 federation helpers. The shared projection helpers (`ingest_federation_operations` / `project_federation_operation` / `project_federated_message` / `FederationIngestResult`) stay in `mod.rs` because they're also called from non-federation paths. |

Net: **mod.rs shrank from 19138 → 17195 lines (-1943)**, 28 handler fn + 51 helper fn moved out. The util re-exports also let me drop the now-unused `DeviceId / ErrorEnvelope / ApiError` imports at the top of mod.rs.

Public re-exports (`pub use module::name`) preserve the `crate::handlers::*` glob in `lib.rs`, so the route table didn't change. `cargo check` clean (only the upstream SDK `unused-qualifications` warning); **72/72 lib unit tests still pass**.

### Pattern reference for next-round extractions

When extracting `<domain>.rs` from mod.rs:

1. `use super::{name, ...}` for parent-private helpers (`auth_or_render`, `now`, `append_audit_log`, the still-in-mod.rs validators) — Rust child modules see parent private items.
2. `use crate::{ids, state::AppState, wire::...}` for non-handler crate items.
3. After deletion, in mod.rs add `pub mod <domain>;` and `pub use <domain>::{handler1, handler2, ...};` so `lib.rs::handlers::*` route registration keeps working.
4. After cargo-check, prune the now-unused imports at the top of mod.rs (unused warnings will tell you exactly which ones).
5. Delete in REVERSE line order from mod.rs so earlier line numbers don't shift.

`git mv src/handlers.rs src/handlers/mod.rs` was used so blame/history is preserved on the bulk of the code.

### Still pending under F1 (next rounds)

The split pattern is now proven; remaining domains can land in independent PRs:

1. **`auth.rs`** (4 fn): `dev_login`, `exchange_session_grant`, `logout` — depends on `session_token_hash`, `token_for`, `bearer_token` (helpers stay in mod.rs for now or move into `handlers/util.rs`).
2. **`account.rs`** (4 fn): `account_register`, `account_me`, `contact_request`, `contact_respond`, `list_contacts`.
3. **`space.rs`** (5 fn): `create_space`, `delete_space`, `export_space`, `add_space_member`, `remove_space_member` + space helpers (`space_owner_matches`, `touch_space`, `is_space_deleted`, `space_visible_to`, ...).
4. **`message.rs`** (3 fn): `send_message`, `revise_message`, `redact_message`.
5. **`reaction.rs` / `read_marker.rs`** (4 fn).
6. **`entity.rs`** (5 fn) + **`relation.rs`** (3 fn) + **`view.rs`** (2 fn) + **`schema.rs`** (4 fn).
7. **`identity.rs`** (6 fn).
8. **`sync.rs`** (5 fn) + sync-cursor helpers.
9. **`events.rs`** (5 fn) + event validators (~20 helpers).
10. **`directory.rs`** (7 fn) + demo data helpers.
11. **`index.rs`** (8 fn).
12. **`repo.rs`** (5 fn).
13. **`authz.rs` / `policy.rs`** (8 fn) — handler shim, real engine already lives in `src/authz.rs`.
14. **`admin.rs`** (1 fn) + admin item builders.
15. **`device.rs`** (2 fn) + **`keys.rs`** (3 fn) + **`device_messages.rs`** (3 fn).
16. **`key_backup.rs`** (4 fn) + **`key_backup_restore.rs`** (~28 fn — the biggest remaining block).
17. **`push.rs`** (5 fn) + **`push_outbound.rs`** (7 fn).
18. **`blob.rs`** (2 fn).
19. **`profile.rs`** (1 fn) + **`describe.rs`** (the pile of describe scaffolds at the top).
20. **`util.rs`** for the truly generic helpers (`render_error`, `now`, `sha256_hex`, `query_param`, `query_list`, `query_flag`, `bearer_token`, `auth_or_render`, `authenticated_session`, `is_valid_*` validators, the policy/push matchers, the canonical-JSON validators, the proof helpers, `OperationPayloadSchema`, `ProofVerifier`, `DevProofVerifier`, blob helpers, etc.).

After the full sweep `mod.rs` should be only the route table + `pub use` re-exports (≤ 200 lines).

## Round-3 progress (2026-05-05) — F1 round 3: 5 more domain modules + branch sync

### Branch sync

- Pushed local `main` (32 commits ahead) to `origin/main` (`6b010d0..59cc7e1`).
- Switched the GitHub default branch from `master` to `main` (`gh repo edit --default-branch main`); local `origin/HEAD` retracked to `origin/main`. `origin/master` is left in place as a safety backout.

### Module breakdown after this round

| File | Lines | Handlers | Notes |
| --- | --- | --- | --- |
| `src/handlers/mod.rs` | **13313** | rest | shrank from 17195 → 13313 this round (**-3882**) |
| `src/handlers/key_backup_restore.rs` | **2143** | 28 | the biggest scaffold block: `keys/backups` CRUD + the entire restore-ticket lifecycle (describe/start/advance/resume/cancel/retry/approval/executor/result/receipt/handoff/bundle/activity/timeline/audit-feed) + restore-state snapshot store (export/import/durability/checkpoints). All scaffolds; each response carries a `todo` field describing the production replacement. |
| `src/handlers/mimi.rs` | 619 | 12 | (round-2) |
| `src/handlers/auth.rs` | **577** | 3 | `dev_login / exchange_session_grant / logout` plus the auth-pipeline helpers exported back to the rest of `crate::handlers`: `auth_or_render`, `authenticated_session`, `is_device_revoked`, `revoke_device_record`, `session_token_hash`, `token_for`. |
| `src/handlers/space.rs` | **554** | 5 | `create_space / add_space_member / remove_space_member / delete_space / export_space` + `render_space_lifecycle / space_owner_matches / touch_space` (re-exported because `touch_space` is also called from the projection writer). The widely-used visibility helpers (`space_has_member`, `space_id_accessible`, `space_visible_to`, …) intentionally stay in `mod.rs` for now; they will move once the directory layer is extracted. |
| `src/handlers/message.rs` | **480** | 3 | `send_message / revise_message / redact_message`. Pulls a long `use super::{...}` import for the shared write-fan-out: `dev_proof`, `next_author_seq`, `ProofVerifier`, `DevProofVerifier`, `projection_event_from_operation`, `append_projection_event`, `project_accepted_operations`, plus the JSON / encrypted-envelope validators. |
| `src/handlers/webrtc.rs` | 408 | 5 | (round-2) |
| `src/handlers/federation.rs` | 396 | 5 | (round-2) |
| `src/handlers/recovery.rs` | 387 | 5 | (round-2) |
| `src/handlers/account.rs` | **337** | 5 | `account_register / account_me / contact_request / contact_respond / list_contacts` + the local `account_response / contact_response` constructors. |
| `src/handlers/util.rs` | 243 | 0 | (round-2) |
| `src/handlers/moderation.rs` | 98 | 1 | (round-2) |

**Total handler tree: 19555 lines** (was 19138 before any extraction; the +417 is mostly per-file module docs and a handful of explicit `use super::{...}` imports). `mod.rs` is now **13313 lines** — down from the original 19138 (**-30.5%**) without renaming a single handler or changing any route registration.

### Round-3 mechanics

- A small bug from round-2 surfaced and was fixed: when `space.rs` was extracted, four `#[handler]` attributes belonging to *the next* fn in line were stranded above `send_message`. They were grouped into a single `sed` deletion pass and removed before `message.rs` was carved out.
- After every extraction this round mod.rs needed unused-import pruning (8 lines across `state::{...}`, `wire::{...}`, and `sha2::{Digest, Sha256}` — the latter went away once `auth.rs` took the token helpers).

### Verification

- ✅ `cargo check` clean (only the upstream SDK `unused-qualifications` warning).
- ✅ `cargo test --lib`: **72 / 72 pass** (same baseline as round-1 / round-2; no regressions).
- ✅ `lib.rs` route table unchanged; every public handler is reachable through the `pub use module::*` re-exports.

### Still open under F1 (next rounds, in suggested order)

1. **`reaction.rs` + `read_marker.rs`** (~4 fn) and **`entity.rs` + `relation.rs` + `view.rs` + `schema.rs`** (~14 fn) — each domain ~200-400 lines once the helpers move with them.
2. **`identity.rs`** (6 fn — describe/resolve/document/log/submit-did-operation/receipts).
3. **`sync.rs`** (5 fn) + the sync-cursor helpers (`SyncCursor`, `parse_and_validate_sync_cursor`, `sync_filter_hash`, `index_query_cursor`, …).
4. **`events.rs`** (5 fn) + the ~25-helper event-validator block (`validate_event_envelope`, `validate_event_proofs`, `event_canonical_source`, `OperationPayloadSchema`, …).
5. **`directory.rs`** (7 fn) + `demo_*` data + `actor_visible_to`.
6. **`index.rs`** (8 fn).
7. **`repo.rs`** (5 fn).
8. **`authz.rs` / `policy.rs`** (8 fn) — handler shim only, real engine already in `src/authz.rs`.
9. **`admin.rs`** (1 fn) + admin item builders.
10. **`device.rs` / `keys.rs` / `device_messages.rs`** (~8 fn).
11. **`push.rs` / `push_outbound.rs`** (~12 fn).
12. **`blob.rs`** (2 fn) + the blob/MIME/sha256-digest helper cluster (still in mod.rs).
13. **`profile.rs`** + the describe scaffolds at the top of `mod.rs` (`server_describe`, `auth_bridge_describe`, `authz_describe`, `policies_describe`, `device_messages_describe`, `key_backups_describe`, `integration_describe`).
14. Move the remaining proof helpers (`ProofVerifier`, `DevProofVerifier`, `validate_proof_*`, `OperationPayloadSchema` & the operation/canonical-JSON validators) into `src/proof.rs` (or `src/handlers/proof.rs`) once the events / message / repo handlers all reach for them through a stable surface.

After (1)–(14) `mod.rs` should be the route table + `pub use` re-exports + `error_catcher` + `wait_for_sync_token` middleware (≤ 200 lines target).

## Round-4 progress (2026-05-05) — collaboration-data CRUD cluster

This round picked up item (1) of the round-3 backlog: 6 modules covering reaction / read_marker / entity / relation / view / schema. They share enough wire-type plumbing that they were natural to extract together — the entire 1647-line block from `add_reaction` through `view_value_key` came out in a single `sed` deletion (after each module was already written) once boundary verification confirmed no in-range fn was called from later positions.

| File | Lines | Handlers | Notes |
| --- | --- | --- | --- |
| `src/handlers/mod.rs` | **11679** | rest | shrank from 13313 → 11679 this round (**-1634**) |
| `src/handlers/key_backup_restore.rs` | 2143 | 28 | (round-3) |
| `src/handlers/mimi.rs` | 619 | 12 | (round-2) |
| `src/handlers/auth.rs` | 577 | 3 | (round-3) |
| `src/handlers/space.rs` | 554 | 5 | (round-3) |
| `src/handlers/message.rs` | 480 | 3 | (round-3) |
| `src/handlers/entity.rs` | **478** | 5 | `create_entity / get_entity / update_entity / delete_entity / list_entities`. Uses the soft-delete projection in `state.projection.entities` and the canonical-JSON validators in `mod.rs`. |
| `src/handlers/view.rs` | **477** | 2 | `create_view / get_view` plus all 14 view-projection helpers (`build_view_projection`, `build_collection_projection`, `build_conversation_projection`, `build_graph_projection`, `build_queue_projection`, `build_kanban_projection`, `build_table_projection`, `build_calendar_projection`, `build_timeline_projection`, `view_required_facets`, `view_required_facets_from_query`, `entity_field_value`, `view_value_key`, `is_supported_view_kind`). `is_supported_view_renderer` and `facet_names_from_value` are `pub` and re-exported because the index handler (still in `mod.rs`) consumes them. |
| `src/handlers/webrtc.rs` | 408 | 5 | (round-2) |
| `src/handlers/federation.rs` | 396 | 5 | (round-2) |
| `src/handlers/recovery.rs` | 387 | 5 | (round-2) |
| `src/handlers/account.rs` | 337 | 5 | (round-3) |
| `src/handlers/schema.rs` | **275** | 4 | `list_schemas / get_schema / register_schema / delete_schema` plus the local helpers `schema_record_to_response`, `is_valid_schema_id`, `is_supported_schema_kind`. The future reducer-side `SchemaRegistryState` (Stream-A3) will consume the same record shape. |
| `src/handlers/util.rs` | 243 | 0 | (round-2) |
| `src/handlers/relation.rs` | **241** | 3 | `create_relation / delete_relation / list_relations`. `cx.relation.update` is intentionally not exposed — the reducer handles patch-merge per Round-1 A1a, and updates ride the canonical event-submit path. |
| `src/handlers/reaction.rs` | **181** | 2 | `add_reaction / remove_reaction`. Uses the `DevProofVerifier` shortcut. |
| `src/handlers/read_marker.rs` | **129** | 2 | `set_read_marker / get_read_markers`. Returns the `state.projection.read_markers` slice for the actor (LWW per scope). |
| `src/handlers/moderation.rs` | 98 | 1 | (round-2) |

Cumulative: `mod.rs` is now **11679 lines, down from 19138 (-39%)** without touching a single route registration or renaming a single public handler. Handler tree total 19702 lines (the +564 net is from per-file module docs and repeated `use super::{...}` headers).

### Round-4 mechanics

- All 6 module files written first, with each `use super::{...}` import list deduplicated against `mod.rs`'s still-private helpers.
- After all files were in place, the entire `1790..=3436` block was deleted from `mod.rs` in one `sed -i` call — much cleaner than the 8 reverse-order deletes round-3 needed, because boundary verification confirmed nothing in-range was called from later code (only the `view::is_supported_view_renderer` external use site at the index handler, which is now reached through the `pub use view::is_supported_view_renderer` re-export in `mod.rs`).
- 16 unused wire-type imports were pruned from `mod.rs`'s top-of-file `use crate::wire::{...}` block (`AddReactionRequest`, `CreateEntityRequest`, `CreateRelationRequest`, `CreateViewRequest`, `EntityResponse`, `ReactionResponse`, `ReadMarkerResponse`, `RegisterSchemaRequest`, `RelationResponse`, `RemoveReactionRequest`, `SchemaResponse`, `SchemasResponse`, `SetReadMarkerRequest`, `UpdateEntityRequest`, `ViewResponse`) plus `SchemaRecord` from the state import group.

### Verification

- ✅ `cargo check` clean (only the upstream SDK `unused-qualifications` warning).
- ✅ `cargo test --lib`: **72 / 72 pass** (same baseline; no regressions).
- ✅ `lib.rs` route table unchanged.

### Still open under F1

In the suggested order from round-3, items (2)–(14) remain:

2. **`identity.rs`** (6 fn — describe / resolve / document / log / submit-did-operation / receipts).
3. **`sync.rs`** (5 fn) + sync-cursor helpers.
4. **`events.rs`** (5 fn) + the event-validator block (~25 helpers — the largest still-coupled cluster in `mod.rs`).
5. **`directory.rs`** (7 fn) + demo-data builders + `actor_visible_to`.
6. **`index.rs`** (8 fn).
7. **`repo.rs`** (5 fn).
8. **`authz.rs` / `policy.rs`** (8 fn) — handler shim only.
9. **`admin.rs`** (1 fn) + admin item builders.
10. **`device.rs` / `keys.rs` / `device_messages.rs`** (~8 fn).
11. **`push.rs` / `push_outbound.rs`** (~12 fn).
12. **`blob.rs`** (2 fn) + blob/MIME/sha256 helper cluster.
13. **`profile.rs`** + the describe scaffolds at the top.
14. Move proof helpers (`ProofVerifier`, `DevProofVerifier`, `validate_proof_*`, `OperationPayloadSchema`, the operation/canonical-JSON validators) into a dedicated `src/handlers/proof.rs`.

---

>
> 当前状态摘要：
> - **代码规模**：`src/` 27.9K 行，`tests/http_api.rs` 5.2K 行（42 tests）。
> - **路由**：~180 个 HTTP 路由全部挂上 router；其中相当一部分是 scaffold/echo（recovery、key-backup restore、push outbound bridge、MIMI、directory 等）。
> - **持久化**：PgStore 仅覆盖 `accounts / sessions / devices / federation_transactions` 四张表；`contacts / space_meta / messages / blobs / push / presence / policy / audit / moderation / webrtc / key_backups / recovery_*` 全部走 MemoryStore fallback —— 进程重启即丢。
> - **Reducer**：130 个注册 event kind 中只完整投影了 28 个（21%）。MLS、key.verification、schema/morph、view、flow、capability、policy、identity disclosure、audit、invite、agent、applet、call 全无 projection。
> - **Authz**：14 种 constraint 实现 3 种；10 种 condition.kind 实现 0 种；invite ↔ grant ↔ policy 三者未联动；obligation 当 inert JSON 透传。
> - **handlers.rs**：单文件 19138 行 / 365 个 fn —— 必须按域拆分后再扩展，否则后续每个特性 PR 都会冲突。
> - **Spec 同步**：`contrix-spec/_report.md` 列出 23 BLOCKING + 30+ MAJOR；其中 ~14 个 BLOCKING 直接落到服务器实现（B-02/03/05/06/07/09/10/11/12/13/14/17/18/22/23）。
>
> 全部任务按 **可并行性** 分组：每个 group 内部独立可并行；group 之间有显式 prerequisite 时已注明。

---

## P0 · Foundation (必须先于大部分扩展工作落地)

> 这一组是**串行 gate**：F1/F2/F3 任一不做，后面的并行扩展都会反复冲突或返工。

| # | 任务 | 涉及文件 | 阻塞下游 |
| --- | --- | --- | --- |
| F1 | 拆分 `src/handlers.rs`（19138 行 / 365 fn）按域成模块：`handlers/{auth,account,space,message,reaction,read_marker,entity,relation,view,schema,identity,sync,events,directory,index,repo,authz,policy,admin,audit,push,push_outbound,device,keys,key_backup,key_backup_restore,recovery,device_messages,federation,webrtc,blob,moderation,mimi,profile,integration}.rs`。原文件保留 `pub use` re-export 一段时间避免 routes 改动同步爆。 | `src/handlers.rs` → `src/handlers/*.rs` | P1/P2 全部 |
| F2 | 把 `MemoryPersistenceStore` 的 `contacts / space_meta / messages / blobs` fallback 升级成 PgStore；为 `push_devices / push_rules / presence / policy_documents / moderation_reports / audit_log / webrtc_sessions / key_backups / recovery_tickets / restore_state_snapshots / outbound_push_cache` 新增 trait + Pg 实现 + memory 实现，迁移当前 `state.rs` 锁里那一坨长期态。`persistence.rs:531` TODO(P0 durable-state) 即此项。 | `src/persistence.rs`、`src/state.rs`、`migrations/*` | P1 federation/MIMI/recovery/key-backup 全部 |
| F3 | 抽出 `src/error.rs` —— 把当前散在 handlers 里的 `error_envelope!` / `error_code` 字面量统一为 enum，并对齐 `contrix-spec/artifacts/registry/error-code-registry.json`（spec B-08：现 42 codes vs 实际 ~20）。同时给 `error_catcher` 走结构化 path。 | `src/handlers.rs::error_envelope`、`src/lib.rs::error_catcher`、新文件 `src/error.rs` | P1 authz / federation / events |
| F4 | 把 lib.rs 里的 `register_contract_operations` + 静态 `CONTRACT_OPERATIONS` 表（spec B-07）替换成由 `artifacts/openapi/contrix-service-api.openapi.yaml` 与 `contract-catalog.json` 生成的 OpenAPI；删除 `// TODO(openapi)` 兼容层。 | `src/lib.rs:518-1327` | OpenAPI 一致性 |
| F5 | **Integration test hang** —— 排查 `account_contacts_and_space_lifecycle_workflow` 和 `admin_collection_surfaces_return_sodmin_shapes` 在单线程下都无限挂起的根因（即使 reducer 改动 stash 后依然挂；与本轮修改无关，是 build break 之前就存在的隐疾）。建议先用 `RUSTFLAGS="--cfg tokio_unstable" RUST_LOG=trace` 跑 + tokio-console 抓阻塞栈，或者把 ratelimit / wait_for_sync_token middleware 临时摘掉做差分。 | `tests/http_api.rs`、`src/ratelimit.rs`、`src/handlers.rs::wait_for_sync_token` | 解锁 CI |
| F6 | **Integration test 失败** —— `auth_keys_device_messages_and_blobs_work` failure 复现 + 修；同样不是本轮改的代码。 | `src/handlers.rs`（`keys_upload`/`keys_query`/`device_messages_*`/`blob_*`） | 解锁 CI |
| F7 | 升级 `#![recursion_limit = "512"]` 仅是治标 —— 真正要做的是 F1 拆 handlers.rs 后让 scaffold JSON 块缩到合理长度；否则一加几个字段就会再次撞限。 | `src/lib.rs`（已加） + F1 | 紧跟 F1 |

---

## P1 · 并行域扩展（F1/F2/F3 之后可同时进行）

下面 6 个 stream **彼此完全独立**，可以分给 6 路并行实现。

### Stream A · Reducer kind handler 扩面（21% → 80%+）

> 每个 sub-task 是单独 PR，互相不冲突；唯一依赖是 F1（被路由到的 ingest 函数已拆出）。projection state 全部按 spec 的 `evaluation_class` 区分（stateless / grant_local / space_state）。

| # | 任务 | 文件 |
| --- | --- | --- |
| A1 | 修 `cx.relation.update` 的死分支（kinds.rs 199 行）+ `cx.membership.unban` 与 `unban` 区分（reducer.rs ~765 行） | `src/reducer.rs`、`src/kinds.rs` |
| A2 | 加 `cx.space.{join_rule, history_visibility, discovery, policy, policy_components, schema, plaintext_visible_services, history_sharing_policy, asset_privacy_policy, moderation_policy, media_service, tombstone, archive, freeze, upgrade, organization, child, parent, inheritance_policy}` 投影 → 新增 `SpaceMetaState`，在 reducer 里 fan-out。覆盖 spec B-15 / B-16 / B-21（`kind=enclave` ⇒ `federation_policy=closed` 默认；`kind=board\|list` ⇒ `boundary_profile=container`）。 | `src/reducer.rs`、`src/state.rs::ProjectionState` |
| A3 | 加 `cx.schema.{define,update}` + `cx.morph.{create,update,archive,restore}` 投影 → `SchemaRegistryState` / `MorphState`（互相独立 PR） | `src/reducer.rs` |
| A4 | 加 `cx.view.{create,update,reconcile}` 投影 → `ViewState`（spec M-34：renderer enum per-kind 限制必须 schema 里 if/then 强制） | `src/reducer.rs`、`src/wire.rs` |
| A5 | 加 `cx.flow.{create,update,archive,restore,convert,move,reorder,branch.*}` 投影 → `FlowState`，含 fractional indexing。同时落地 spec B-19：`Message.branch` 由 enum 改 `^[a-z][a-z0-9_]{0,63}$`。 | `src/reducer.rs`、`src/wire.rs` |
| A6 | 加 `cx.capability.{grant,delegate,revoke,derived}` 投影 → `CapabilityState`（喂下游 effective_grants） | `src/reducer.rs` |
| A7 | 加 `cx.policy.{set,rule,action}` 投影 → `PolicyState`（与 P1-Stream-D 联动） | `src/reducer.rs` |
| A8 | 加 `cx.invite.{create,cancel,accept,third_party,claim,revoke}` 投影 → `InviteState`（spec M-10：补 invite/notification 的 auth_refs） | `src/reducer.rs` |
| A9 | 加 `cx.account.{status,blocklist}` + `cx.account_data.set` 投影（spec B-17：补 account.status / moderation.report / moderation.frank 进 state-event 名册） | `src/reducer.rs` |
| A10 | 加 `cx.moderation.{report,frank}` 投影；联动 P1-Stream-E 的 moderation pipeline | `src/reducer.rs` |
| A11 | 加 `cx.audit.{accessed, ryw_receipt}` 投影 → `AuditReceiptState`；同时在 catalog 里**注册 `cx.audit.ryw_receipt` event kind**（spec B-13） | `src/reducer.rs`、`contrix-spec/artifacts/registry/contract-catalog.json` |
| A12 | 加 `cx.identity.{disclosure_policy,disclosure_receipt,presentation_request,presentation_response}` + `cx.did.proof` + `cx.session.grant` 投影 | `src/reducer.rs` |
| A13 | 加 `cx.device.{authorized,revoked,list_update}` 投影 → 与 P1-Stream-F 的 device inventory 写穿 | `src/reducer.rs` |
| A14 | 加 `cx.key.verification.*`（8 个子 kind）投影 → `KeyVerificationState`，含 SAS/QR 一次性消费、设备签名绑定、replay 阻挡（spec M-23） | `src/reducer.rs` |
| A15 | 加 `cx.mls.{proposal,genesis,commit,commit_failed,welcome,keypackage,epoch}` 投影 → `MlsGroupState`；处理 spec M-22 的 history-key 撤销/销毁顺序 | `src/reducer.rs` |
| A16 | 加 `cx.space_key.{share,withheld,share_audit}` 投影 → `SpaceKeyState` | `src/reducer.rs` |
| A17 | 加 `cx.member.state` + `cx.profile.{update,space_override}` 投影 | `src/reducer.rs` |
| A18 | 加 `cx.mimi.room_binding`、`cx.sovereign.did_policy`、`cx.organization.{discovery,moderation_policy}` 投影 | `src/reducer.rs` |
| A19 | spec B-09：`redact` reducer 必须保留 `actor_seq`（当前 `cleared` 把 attachments/mentions/relations 扁平化是错的；`hashes` 应清掉而不是保留） | `src/reducer.rs` |
| A20 | spec B-18：state_key 复合键（`a\|b\|c`）改成 sha256/percent-encode 编码，加碰撞防护 | `src/reducer.rs`、`src/ids.rs` |

### Stream B · Authz / Capability / Policy 引擎补全

> 内部 sub-task 大部分独立；B1（schema 字段对齐）需要先做，B2..B12 之后并行。

| # | 任务 | 文件 |
| --- | --- | --- |
| B1 | 对齐 grant 信封 shape（spec B-02）+ 统一 constraint schema（spec B-04 + B-05），补 `recurrence / max_duration / sensitive_fields / allowed_view_kinds / approval_threshold / condition.kind`；删除 `condition.when` 字符串 DSL | `src/authz.rs`、`src/wire.rs`、spec mirror |
| B2 | 实现 11 种缺失 constraint：`field_access / scope_limitation / delegation_control / rate_limiting / approval_workflow / claim_based / accountability / encryption_requirement / container_move / visibility_control / resource_limit / edit_window / device_session`（每种 1 个 sub-PR） | `src/authz.rs::evaluate_constraint` |
| B3 | 实现 10 种 `condition.kind`：`object_is_owned_by_actor / actor_is_assignee / ...`；当前全部 fail-open | `src/authz.rs` |
| B4 | grant-constraint 加 `evaluation_class: enum("stateless","grant_local","space_state","external")` 字段并据此分桶缓存（contrix-spec _todos B4/B5 同步） | `src/authz.rs`、spec schema |
| B5 | 改写决策算法：deny / quarantine / require_review 一律 "any-hit-wins"；priority 仅用于 allow 诊断（contrix-spec _todos B3） | `src/authz.rs::highest_priority_decision` |
| B6 | 把 reducer 里的 `cx.capability.*`（A6）/`cx.invite.*`（A8）投影喂进 `effective_grants()` —— 当前只回直接 grant，没有传递/委托/撤销链 | `src/authz.rs`、`src/handlers/authz.rs`（F1 后） |
| B7 | invite ↔ grant 联动：accept invite 自动生成 grant；revoke invite 自动撤销悬挂的 grant；和 audit 关联 | `src/handlers/authz.rs`、`src/handlers/invite.rs` |
| B8 | 实现 capability lattice（auth_weight 11 档） —— 当前是平面布尔。spec M-09 要求显式 causal_depth tie-break（v1.x 也可，但留 todo） | `src/authz.rs` |
| B9 | policy_check + grant 评估合并：现 `policy_check` 与 `authz_check` 互不知晓，决策不一致；联调成单一 evaluator | `src/handlers/authz.rs`、`src/handlers/policy.rs` |
| B10 | obligation 真正执行：当前只是 echo JSON。绑定到 reducer / 写路径 / quarantine 写穿 | `src/handlers/policy.rs` |
| B11 | revocation 不再仅 `grant.revoked` 单 bool —— 加批量/scope/time-window/CRL 撤销；联动 federation 撤销 fan-out（spec M-18） | `src/authz.rs` |
| B12 | policy decision 缓存 TTL 由 `evaluation_class` 决定，而非硬编码 5 分钟 | `src/authz.rs`、`src/state.rs` |

### Stream C · Federation 与 MIMI 上桥

> Stream C 内部 sub-task 全部独立。F2 提供持久化前可能跑只有 in-memory 的版本，但落地 production 需 F2 完成。

| # | 任务 | 文件 |
| --- | --- | --- |
| C1 | spec B-06：federation signature transcript 全量切到 RFC 9421（`@method / @target-uri / @authority / content-digest / created / expires`）；移除 legacy 字段名 | `src/handlers/federation.rs`（F1 后） |
| C2 | `federation_push_operations` 把 ingest 结果写穿到 `federation_operations` 持久表（不再丢锁）；实现 idempotency key（spec M-20） | `src/handlers/federation.rs`、`persistence.rs` |
| C3 | `federation_pull_operations` 改读持久表 + cursor，重启后可恢复；当前 in-memory snapshot 重启清零 | 同上 |
| C4 | `federation_space_members` 替换 hardcoded "join" placeholder，改读 reducer membership state（依赖 A2） | 同上 |
| C5 | `federation_verify_actor` 真正校验签名 / DID document / key set；返回 `validation_class` enum 而非 bool（spec M-19） | 同上 |
| C6 | revocation fan-out TTL + 重试策略（spec M-18） | `src/handlers/federation.rs` |
| C7 | MIMI `room_update / notify / room_message` 真正落进 cx.* event ingest，而不仅写 audit log；同时移除 demo "alice" 映射 | `src/handlers/mimi.rs` |
| C8 | MIMI `consent_request / consent_update` 走 P1-Stream-D 的 consent state machine + 持久化 | 同上 |
| C9 | MIMI `key_material` 真正生成/取 KeyPackage（联动 A15）；移除 `full_mls_keypackage_claim_not_implemented` 字样 | 同上 |
| C10 | MIMI `identifiers_query` 走真正的 directory（Stream E），删 hardcoded alice | 同上 |
| C11 | MIMI `report_abuse` / `proxy_download` 走 F2 的持久 moderation/blob 表 | 同上 |
| C12 | MIMI provider/protocol directory 由 config 驱动，不再静态返回 | `src/handlers/mimi.rs` |

### Stream D · Recovery / Key Backup / Restore-state（46+ scaffold endpoint 落地）

> 当前这块全是 stub —— `recovery/discovery|readiness|live-snapshot|stack-bundle` + `keys/backups/restore-state/*` + `keys/backups/restore-tickets/{ticket_id}/*`（执行器、审批、活动、时间线、receipt、bundle、audit-feed、materialized-device-handoff）。所有 handler 都返回 `scaffold_*` 字段并带 TODO。
>
> 下面 sub-task 共享一个数据模型 D1，落地后 D2..D11 可并行。

| # | 任务 | 文件 |
| --- | --- | --- |
| D1 | 设计并落地 `RecoveryTicket` / `RestoreCheckpoint` / `RestoreApproval` / `RestoreExecutorRun` / `RestoreReceipt` 数据模型 + Pg/memory store + state machine（pending → approved → enqueued → running → materialized → completed/failed/canceled） | `persistence.rs`、新 `src/recovery.rs`、`migrations/*` |
| D2 | `keys/backups` PUT/GET/DELETE/LIST 由进程内存换成 D1 的 store；schema 校验补全（cx.schema.key_backup.v1，spec B-11） | `src/handlers/key_backup.rs` |
| D3 | restore ticket lifecycle handlers：`describe / start / advance / resume / cancel / retry`（每个 1 PR） | `src/handlers/key_backup_restore.rs` |
| D4 | restore approval：`approvals/status / approvals/submit` —— 真正 reviewer 授权 + quorum + 审计 | 同上 |
| D5 | restore executor：`executor/{status,enqueue,start,complete}` —— 持久 worker lease/heartbeat + 失败补偿 | 同上 |
| D6 | restore artifact endpoints：`result / receipt / bundle / activity / timeline / audit-feed / materialized-device-handoff` —— 不再合成 dummy ID | 同上 |
| D7 | restore-state snapshot 持久化：`describe / export / import / durability / checkpoints` 走 D1 store + 信任/新鲜度策略 | 同上 |
| D8 | `recovery/discovery` 用真实 service discovery + DID-bound audience 元数据 | `src/handlers/recovery.rs` |
| D9 | `recovery/readiness` 跑真实 storage / authz / policy / crypto 健康检查 | 同上 |
| D10 | `recovery/live-snapshot` 改 actor-scoped 仪表盘 + 分页 + 隐私边界 | 同上 |
| D11 | `recovery/stack-bundle` 由 `recovery/contract-stack` 的真实生成产物组装；移除 inline path 列表 | 同上 |
| D12 | spec M-28：did:plc `degraded_mirror_only` 7 天硬限制加宽限/延期机制 | `src/handlers/identity.rs` |

### Stream E · Directory / Search / Moderation 真实数据

> 当前 `search_organizations / search_actors / search_users / resolve_handle / resolve_organization` 全部是 demo_actors 内嵌固定数据；`search_spaces` 没有 cursor。

| # | 任务 | 文件 |
| --- | --- | --- |
| E1 | 在 F2 的 PgStore 里加 `actors`、`organizations`、`handles` 表 + index，directory handler 读真表 | `migrations/*`、`persistence.rs` |
| E2 | `search_spaces` 加 cursor + 排名 + 隐私可见性过滤（不再 hardcoded `public_only=false`） | `src/handlers/directory.rs` |
| E3 | 反枚举：rate-limit / 同意 / 模糊匹配（spec 安全章节，防 directory 遍历） | 同上 |
| E4 | moderation pipeline：`moderation_report` 写 D1/F2 持久表 + 异步审核工作流 + reducer A10 联动 | `src/handlers/moderation.rs` |
| E5 | `moderation/report` 加 SLA / 状态查询（reporter-visible state） | 同上 |

### Stream F · Push / Device / Crypto / Privacy

| # | 任务 | 文件 |
| --- | --- | --- |
| F-1 | spec B-14：DID 不能进 push payload / TURN username / push `sender` 字段 —— 全路径换 Space-scoped pairwise pseudonym 或 ephemeral token；加 conformance MUST_NOT 测试 | `src/handlers/push.rs`、`src/handlers/webrtc.rs`、`src/handlers/push_outbound.rs` |
| F-2 | `keys/upload / query / claim` 走 PgStore 持久化（当前 `handlers.rs:9830` TODO(P0 durable-state)）；revocation propagation 与 reducer A13 联动 | `src/handlers/keys.rs`、`persistence.rs` |
| F-3 | spec B-10：KeyPackage shape 统一到 `principal_id/device_id/keypackage_id/device_signature/expires_at` | 同上 |
| F-4 | spec B-11：`secret_storage` 与 `key_backup` 合并到单一 `cx.schema.key_backup.v1` + `domain` enum；HKDF info per domain | `src/handlers/key_backup.rs`、wire schema |
| F-5 | spec B-12：MLS GroupContext extension `cx_app_state_ref` 分配私用 codepoint（0xF000–0xFFFF），写进扩展注册表 | spec artifact + `src/wire.rs` |
| F-6 | spec B-22：encrypted attachment `key_ref` shape 切到 object 形式 `{algorithm, group_state_ref}`；不再字符串 `"mls_epoch:42"` | `src/handlers/blob.rs`、`src/wire.rs` |
| F-7 | spec B-23：blob metadata 加 `space_id` 关联 + 下载/GC 时校验 | `src/handlers/blob.rs`、`migrations/*` |
| F-8 | push outbound bridge：替换 process-memory cache（`handlers.rs:1393–1719` 一堆 TODO(push-outbound)）为持久 snapshot store，加 etag/freshness、首次 fetch 持久化、契约漂移 fail-closed | `src/handlers/push_outbound.rs` |
| F-9 | `auth/session-grant/exchange` 与 `push/register-device` 的 session-grant bridge（`handlers.rs:1957 / 18739` TODO）替换为 coauth-backed introspection + audience 绑定 + session-public-key proof verification | `src/handlers/auth.rs`、`src/handlers/push.rs` |
| F-10 | WebRTC sessions / signals 持久化（F2 后）；ICE config 不再返回空数组 | `src/handlers/webrtc.rs` |
| F-11 | profile/presence 走 F2 的 presence store；presence/typing 区分 ephemeral vs durable 通道 | `src/handlers/profile.rs` |

---

## P2 · Sync / State-resolution / 一致性

> 这一层依赖 P1-Stream-A 提供更完整的 reducer state；可与 P1-Stream-B/C/D 并行。

| # | 任务 | 文件 |
| --- | --- | --- |
| S1 | `client_sync` 把 `cx:cursor:` 与 reducer event 序列真正映射（`handlers.rs:7623` TODO(P0 sync)） | `src/handlers/sync.rs` |
| S2 | `snapshot-chunk` 由单 JSON chunk 切成确定性多 chunk（`handlers.rs:7794` TODO(P1 snapshot)） | 同上 |
| S3 | spec B-03：history_visibility (`invited` / `restricted`) 三处分歧统一到 reducer 单一解释 | `src/reducer.rs`、`src/handlers/sync.rs` |
| S4 | spec M-15：所有 sync/directory 响应里 ID 前缀确保 `cx:space:` 而非 `space:` | grep + fix |
| S5 | spec M-16：sync subscription 里 `$ME` / `*` 通配语义形式化 + 校验 | `src/handlers/sync.rs` |
| S6 | spec M-09 / M-10 配套：补 4 个 state-resolution conformance vector（与 spec 协同） | tests + spec |
| S7 | `index/debug/reducer` 的内存 snapshot 换成持久投影（`handlers.rs:6894` TODO(P1 reducer-debug)） | `src/handlers/index.rs` |

---

## P3 · 代码质量 / 可观测性 / 安全审计（贯穿全程，可与上面并行）

| # | 任务 | 文件 |
| --- | --- | --- |
| Q1 | 把所有 handler 切到 Salvo `#[endpoint]` extractor + `ToSchema` response type，删除 `register_contract_operations` compat 表（`lib.rs:519` TODO(openapi)） | `src/handlers/*`、`src/lib.rs` |
| Q2 | spec M-01：彻底移除 `event_type`，仅保留 `event_kind`；删 dead error `aad_ambiguous_kind` | `src/wire.rs`、handlers、tests |
| Q3 | spec M-02..M-07：字段命名漂移统一（`principal_id/subject/holder_did`、`session_key_pub/session_public_key`、`Proof.kind`、`read_marker.id` pattern 等） | wire + handlers |
| Q4 | `src/artifacts.rs:147` 的 `panic!("invalid embedded Contrix ...")` 改为构建期校验（build.rs / 启动期 fatal-but-typed），不要运行时 panic | `src/artifacts.rs`、`build.rs`（新） |
| Q5 | 补 tracing：每个 handler 入口 `instrument(span)`，带 actor/space/event_kind；当前几乎无可观测信号 | `src/handlers/*` |
| Q6 | rate-limit 由 ratelimit.rs 单进程 → 共享 store（Pg/Redis）；当前重启即清 | `src/ratelimit.rs` |
| Q7 | tests 拆分：现 `tests/http_api.rs` 一个文件 5233 行 / 42 test。按 Stream A..F 切到 `tests/{auth,reducer,authz,federation,mimi,recovery,...}.rs`，使共享 `setup` 抽到 `tests/common/mod.rs` | `tests/*` |
| Q8 | 端到端契约测试：用 spec `artifacts/fixtures/*` 跑 `submit → reduce → query` round-trip，作为 conformance gate | `tests/conformance.rs`（新） |
| Q9 | dev_login / `admin/{resource}` 等 dev-only path 加 `#[cfg(not(feature = "production"))]` 或运行时 hard guard，避免误开 prod（`handlers.rs:8633` TODO(P1 admin)） | `src/handlers/admin.rs` |
| Q10 | 安全审计：`SERVERX_DEVELOPMENT_MODE=false` 路径上的所有"接受" branch 全部走真实 proof 校验 —— 写一组负向 conformance test | `tests/security.rs`（新） |
| Q11 | CI：跑 `cargo clippy -- -D warnings` + `cargo fmt --check` + `python ../contrix-spec/tools/artifact_pipeline.py check`（漂移闸门） | `.github/workflows/*` |

---

## 并行调度建议

| 时间线 | 可并行 stream |
| --- | --- |
| **Sprint 1 (foundation gate)** | F1 → F3 → F4（顺序）；F2 的 schema 设计可 F1 时并行 |
| **Sprint 2 (并行扩面)** | A · B · C · D · E · F 六路并行（不同工程师）；P2 部分 sub-task（S3/S4/S5）也可并 |
| **Sprint 3 (一致性 + Q)** | A19/A20 + S1/S2/S6/S7 + Q1..Q11 并行 |

**冲突点**（必须 serialize）：
- Stream A 的 reducer 改动与 Stream B 的 effective-grants reducer 喂入 → A 先合，B 跟上
- Stream C 的 federation_space_members → 必须等 A2（SpaceMetaState）和 reducer membership 投影
- Stream D-1 的 RecoveryTicket model → D2..D11 全依赖
- Stream F-2 的 PgStore key store → A13/A14/A15 reducer 写穿点依赖
- Q1（OpenAPI 切 `#[endpoint]`） → 必须在 F1（拆文件）之后；Q1 与 P1 各 stream 不冲突，但要注意 PR rebase 频率

## 不在本轮范围（v1.x 留底）

- `auth_weight` 11 档刻度重构成 `(governance_layer, authority_kind)` lattice（B8 仅做最小占位）
- spec M-38 / M-39 / M-40：applet 命名空间、agent endpoint 生命周期、MIMI room_binding 生命周期
- 多 region / 跨服务部署（当前 soland 是单进程 reference）
- 完整 IANA codepoint 申请（B-12 仅分配私用区段）
