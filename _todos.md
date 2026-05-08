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

| # | Status | Task | Files | Notes |
| --- | --- | --- | --- | --- |
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
| **T1-1** ✅ | `[x]` (2026-05-07) **Done**. `trait ReducerKind` lives in `src/reducer/registry.rs` with `kind()`, `cardinality()`, `component()`, `subject_for_event()`, `project()`. Per-kind impls live in `src/reducer/kinds_impl.rs` (T1-2 will split into per-file modules). Dispatcher `ReducerRegistry` iterates `BTreeMap<&'static str, Box<dyn ReducerKind>>`; lookup is `O(log n)`. `ProjectionState::apply` is now a 1-line `registry().project(operation, self, hlc)`. Cached via `OnceLock`. **47 kinds registered**: 26 active projecting (legacy `cx.message/reaction/entity/relation/membership/space.{create,update,destroy}`) + 21 Phase 1-5 stubs (17 per-facet space + `cx.space.host`/`host.transfer` + `cx.consent.grant`/`revoke` + `cx.member.state`). Stubs project as `Ignored` pending T1-3 but their subject derivation is fully wired (per spec Phase 1 typed payload fields). 84 lib tests pass (was 77 + 7 new T1-1 tests). | `src/reducer.rs`, `src/reducer/registry.rs` (new), `src/reducer/kinds_impl.rs` (new) | unblocks T1-3 / T2-16 / T6-F-7..10 |
| **T1-2** ✅ | `[x]` (2026-05-07) **Done**. `src/reducer/kinds_impl.rs` deleted; replaced with `src/reducer/kinds/` directory (13 per-domain files): `mod.rs` (shared `singleton_state_kind!` / `non_state_kind!` / `legacy_membership_kind!` / `consent_kind!` macros — children inherit them via macro_rules textual hoisting, no `pub(crate) use` needed) + `messages.rs` (4 kinds), `reactions.rs` (2), `read_marker.rs` (1), `entity.rs` (5), `relation.rs` (3), `container.rs` (2), `membership.rs` (6), `space_lifecycle.rs` (3), `member_state.rs` (1), `space_facets.rs` (15), `space_inheritance.rs` (1), `space_host.rs` (2), `consent.rs` (2). All 47 ReducerKind impls relocated; existing `tests` mod moved to `kinds/mod.rs`. Updated `src/reducer.rs` (`pub mod kinds_impl;` → `pub mod kinds;`, dropped collided `kinds` use, qualified `kinds::CX_MEMBERSHIP_*` → `crate::kinds::CX_MEMBERSHIP_*`) + `src/reducer/registry.rs` glob-import (`kinds_impl::*` → `kinds::*`). Pure file shuffling; behaviour identical. 84/84 lib tests pass; all test binaries build clean. | `src/reducer/kinds/*` | T1-1 done |
| **T1-3** | Land each remaining kind project body. v1 standard kinds left to project (currently `Ignored` stubs under `src/reducer/kinds/{space_facets,space_inheritance,space_host,consent,member_state}.rs`): `cx.space.policy / join_rule / history_visibility / discovery / policy_server / policy_components / history_sharing_policy / asset_privacy_policy / moderation_policy / plaintext_visible_services / media_service / schema / inheritance_policy / archive / freeze / tombstone`, `cx.space.host / host.transfer`, `cx.consent.grant / revoke`, `cx.member.state`, plus everything not yet in the registry: `cx.schema.*`, `cx.morph.*`, `cx.view.*`, `cx.flow.*`, `cx.capability.*`, `cx.policy.*`, `cx.invite.*`, `cx.account.*`, `cx.account_data.*`, `cx.moderation.*`, `cx.audit.*`, `cx.identity.*`, `cx.did.proof`, `cx.session.grant`, `cx.device.*`, `cx.key.verification.*` (8), `cx.mls.*` (7), `cx.space_key.*` (3), `cx.profile.*`, `cx.mimi.room_binding`, `cx.sovereign.did_policy`, `cx.organization.*`. Per-kind PRs typically promote the kind out of its grouped stub file into a dedicated `src/reducer/kinds/<kind>.rs` as the body lands. | `src/reducer/kinds/*` | T1-1 + T1-2 done |
| **T1-4** | spec B-09 — `redact` reducer must preserve `actor_seq`. Currently `cleared` flattens attachments/mentions/relations; `hashes` must be cleared, not retained. | `src/reducer/kinds/messages.rs` (`MessageRedact` + `Redaction`) → `ProjectionState::apply_redaction` in `src/reducer.rs` | |
| **T1-5** ⚠ ✅ | `[x]` (2026-05-07) **Done as part of T1-1**. `StateCardinality::{Singleton, PerSubject, None}` + `subject_for_event` is the canonical model; all 47 registered kinds declare cardinality + subject derivation. Composite subjects (`cx.flow.branch.member` etc., when added) use `subject_compose` from `src/ids.rs`. `assert_no_legacy_state_key` rejects payload-level `state_key` field as `ReducerKindError::LegacyStateKey`. | `src/reducer/registry.rs` | spec Phase 1 §4.3 |
| **T1-6** ✅ | `[x]` (2026-05-07) **Done as part of T1-1**. `ComponentDescriptor { component_type, component_version, criticality }` is on every registered kind. `Criticality::{Required, Optional, Ignore}` enum present. Runtime "unknown component → criticality dispatch" wiring is T1-3 territory (we currently call `project()` on every kind that's registered; unknown kinds fall through to `ProjectionEffect::Ignored`). | `src/reducer/registry.rs`, `src/reducer/kinds/*` | spec Phase 2 §4.4 |
| **T1-7** ✅ | `[x]` (2026-05-07) **Done as part of T1-1**. All 17 per-facet `cx.space.<facet>` + `cx.space.host` + `cx.space.host.transfer` + `cx.consent.grant` + `cx.consent.revoke` registered with subject derivation; `project()` is `Ignored` pending T1-3. | `src/reducer/kinds/{space_facets,space_inheritance,space_host,consent,member_state}.rs` | T1-1 done |

---

## Tier 2 · Wire format reset

> Drop the legacy field-name drift in one breaking pass — no shim, no alias.
> spec M-01..M-07 collapses to "delete the legacy names, regen tests".

| # | Task | Files | Notes |
| --- | --- | --- | --- |
| **T2-1** ✅ | `[x]` (2026-05-07) **Done**. `aad_ambiguous_kind` was already absent from the codebase. `ProjectionEventRecord.{event_type, input_event_type, canonical_event_type}` collapsed to a single `event_kind: String` ([src/state.rs:172-175](src/state.rs:172-175)). Wire output emits only `event_kind` — updated [src/routing/projection.rs](src/routing/projection.rs) (`projection_event_json`, `projection_event_from_operation`, `event_is_visible`, `redaction_targets_from_events`, SQL `SELECT event_type AS event_kind` aliasing on read), [src/routing/space.rs:372](src/routing/space.rs:372) (snapshot export), [src/routing/device.rs:143](src/routing/device.rs:143) (pairing-authorized envelope). Dropped the `or_else(|| ... "/delivery/event_type")` legacy fallback in [src/routing/push_outbound.rs:568](src/routing/push_outbound.rs:568). Test assertions updated: [tests/http_api.rs:1972-1981](tests/http_api.rs:1972), [3109](tests/http_api.rs:3109), [4923-4929](tests/http_api.rs:4923) (added negative assertions that legacy keys are absent). DB column rename (`events.event_type → event_kind`) is a separate Diesel migration tracked under "DB schema follow-up". 84/84 lib tests pass; all test binaries build clean. | `src/state.rs`, `src/routing/{projection,space,device,push_outbound}.rs`, `tests/http_api.rs` | spec M-01 |
| **T2-2** | spec M-02..M-07 — unify `principal_id / subject / holder_did`, `session_key_pub / session_public_key`, `Proof.kind`, `read_marker.id` pattern. One name per concept; delete the others. | `src/wire.rs`, handlers | spec M-02..M-07 |
| **T2-3** ✅ | ~~every sync/directory response uses the `cx:space:` prefix~~ Done — all sync/directory responses already emit `cx:space:` (verified by grep). Removed the dead legacy-`space:` strip workaround in `src/routing/authz.rs:47-49` so the `authz.check` request resource string is forwarded verbatim per spec M-15. | grep + fix | |
| **T2-4** | Grant envelope shape and constraint schema aligned to v1.0 `grant-constraint.schema.json` — 8 family (`temporal / field_access / type_restriction / scope_limitation / delegation_control / quota / claim_based / confidentiality`) + `subtype`. Drop the legacy 14-name model and the `condition.when` string DSL. | `src/authz.rs`, `src/wire.rs`, spec mirror | B1 (old plan) |
| **T2-5** | spec B-10 — KeyPackage shape unified to `principal_id/device_id/keypackage_id/device_signature/expires_at`. | `src/routing/keys.rs`, wire | F-3 (old plan) |
| **T2-6** | spec B-11 — merge `secret_storage` and `key_backup` into `cx.schema.key_backup.v1` + `domain` enum; HKDF info per domain. | `src/routing/key_backup.rs`, wire | F-4 (old plan) |
| **T2-7** | spec B-22 — encrypted attachment `key_ref` switched to object form `{algorithm, group_state_ref}`; drop string `"mls_epoch:42"`. | `src/routing/blob.rs`, `src/wire.rs` | F-6 (old plan) |
| **T2-8** | spec B-14 — DIDs MUST NOT appear in push payload / TURN username / push `sender`. Replace with Space-scoped pairwise pseudonym or ephemeral token; add MUST_NOT conformance tests. | `src/routing/{push,webrtc,push_outbound}.rs` | F-1 (old plan) |
| **T2-9** | spec B-23 — blob metadata adds `space_id` association + download/GC checks. | `src/routing/blob.rs`, `migrations/*` | F-7 (old plan) |
| **T2-10** | spec B-12 — MLS GroupContext extension `cx_app_state_ref` allocated a private codepoint (0xF000–0xFFFF) and registered. | `contrix-spec/spec/v1/artifacts/`, `src/wire.rs` | F-5 (old plan) |

### Tier 2.6 · Move / Anchor / Lattice runtime ⚠ 🔒

> 起源：`contrix-spec` 2026-05-08 用 Move/Anchor/Lattice 三原语替换旧 state slot 模型。详见根 [`../_todos.md` C10.B](../_todos.md)。
>
> Gate: contrix-rust-sdk M0-M12 已就位 (2026-05-08, SDK 0.2.0)，typed Move/Anchor/Lattice + apply_anchor 算法 + store traits 全可用。
>
> **2026-05-08 进度**：MAL-0 (旧产物清理，C11 已完成) + MAL-2 (`POST /api/v1/moves` 提交入口) + MAL-4 (`POST /api/v1/anchors` apply_anchor end-to-end) 已落地。AppState 持有 SDK `MemoryMoveStore` / `MemoryAnchorStore` / `MemoryCellStore` / `MemoryCellRegistry`（生产环境可换成 Pg 后端，trait 不变）。剩余 MAL-1 (LatticeKind trait 替代 ReducerKind, 47 stub 重写) / MAL-3 (anchorer 签发 worker) / MAL-5..MAL-15 是后续工作。

| # | Task | Files | Notes |
| --- | --- | --- | --- |
| **MAL-0** ⚠ | `[x]` | 旧产物清理：删除 `src/host_endorser.rs`（如已落地）、`src/routing/federation_hub.rs`、reducer kinds 中 `space_host.rs` / `space_host_transfer.rs` stub。回退 ids.rs / wire.rs 中 host_did / endorsed_at / space_writer_model 引用。同步 SDK W6/W7/W8 删除。 | `src/`、`tests/` | 根 C11 |
| **MAL-1** ⚠ | `[ ]` | `LatticeKind` trait 替代 `ReducerKind`（按 cell_family 而非 event_kind 注册）。47 个旧 stub 移除或重写为 cell_family 实例（messages / reactions / membership / capability / consent / mls_epoch / covered_frontier / anchorer / 等）。 | `src/reducer/` 整体重命名 → `src/lattice/` 或保留 reducer 名但语义改 | T1 trait 替换 |
| **MAL-2** ⚠ | `[x]` | Move 提交入口 `POST /api/v1/moves` | `src/routing/move_anchor.rs` | 已落地 (2026-05-08)：`submit_move` 接收 typed `Move`，调 SDK `verify_move` 走 5 步流水线（structural + sig payload_hash + capability placeholder + preconditions + effect-shape via cell registry），通过则 `MoveStore::put_pending`；返回 `{move_id, state: pending\|rejected, reason?}`。JWS 校验当前 placeholder（accept any）— 收紧到 production-mode signature verifier 是 T7-9 的范围。 |
| **MAL-3** ⚠ | `[ ]` | Anchorer 签发 worker | 新 `src/anchorer.rs` | 节点是 anchorer 时按 deterministic_order 收 pending Move → verify_move(M, pre_state) → 收纳进 Anchor.frontier → 计算 state_root → 单签 / multi / threshold → 发布 Anchor |
| **MAL-4** ⚠ | `[x]` | Anchor 接收 / 验证 / apply `POST /api/v1/anchors` | `src/routing/move_anchor.rs` | 已落地 (2026-05-08)：`submit_anchor` 调 SDK `apply_anchor` 走 8 步算法（structural → predecessor_refs 已知 → frontier 单调 → joined pre_state → deterministic_order 批 verify_move → atomic effect append → recompute state_root + 比对 → persist Anchor + mark Moves anchored）。state_root 不匹配自动 rollback。返回 `{anchor_id, accepted_move_ids[], rejected_moves[{move_id,reason}], post_state_root}`。`AnchorReject` 映射 → wire error_code (`schema_violation` / `internal_error`) + 409 Conflict。 |
| **MAL-5** ⚠ | `[ ]` | per-cell Lattice runtime | 新 `src/lattice/` | 6 个 Lattice 实现（或调用 SDK lattice crate）；effective state 物化为 `(cell_id, value | bottom_diagnostics)` 表 |
| **MAL-6** | `[ ]` | `bottom_escalation_after_ms` 后台 scanner | `src/anchorer.rs` 或独立 worker | 超时 bottom emit notification；不自动选 winner |
| **MAL-7** | `[ ]` | `cx.consent.grant` / `revoke` 改写为 consent cell Move | `src/reducer/kinds/consent_*` 改写或重命名 | grant=add tag, revoke=remove tag 在 `cx:cell:cx.component.consent.v1:<consent_id>`（or-set） |
| **MAL-8** | `[ ]` | invite handler 改 consent gate 为 consent cell join 值查询 | `src/routing/invites.rs` | 不存在 / revoked → quarantine inbox 或 `consent_required` reject |
| **MAL-9** ⚠ | `[ ]` | MLS commit 走 Move 路径 | `src/mls.rs`、新 `src/lattice/covered_frontier.rs` | commit 是 Move：preconditions 含 `mls_epoch_cell.head_eq(prev_epoch)` + `covered_frontier_cell.contains(governance_frontier)`；缺 covered_frontier 不阻塞 governance Move |
| **MAL-10** | `[ ]` | Move 状态在 sync wire 上的暴露 | `src/sync.rs`、`src/routing/events.rs` | pending_anchor / effective / failed_precondition / failed_bottom / rejected_anchor / anchorer_paused（取代 T2-19 `state_binding_status`） |
| **MAL-11** | `[ ]` | Anchor compaction 流程 | `src/anchorer.rs` | signed compaction Anchor：frontier = effective_anchor_view，state_root 等价；保留 bottom diagnostics + 签名验证链 |
| **MAL-12** ⚠ | `[ ]` | federation 改造（去除 hub / peer_mesh 分叉路径） | `src/routing/federation*.rs` | 统一 Move 广播 + Anchor 拉取/推送；多 leaf 通过 effective_anchor_view 收敛 |
| **MAL-13** | `[ ]` | Snapshot / GC 规则更新 | `src/persistence.rs`、`src/routing/repo.rs` | 未被任何 Anchor frontier 覆盖且未被 active pending / recovery Move 引用 → MAY GC；已 Anchor Move MUST 保留审计 stub |
| **MAL-14** | `[ ]` | `redact` reducer 改写 | `src/reducer/kinds/messages.rs` 或新 `src/lattice/redaction.rs` | redaction effect 写 redaction cell（与目标 message cell 同 subject 的并行 cell）；ordered-log entry id 不删除，projection 隐藏 |
| **MAL-15** | `[ ]` | sodmin admin 接口暴露 anchor / lattice 字段 | `src/routing/admin.rs` 或 spaces.rs | `/api/admin/v1/spaces/{id}` 暴露 `anchor_profile` / 当前 anchorer cell value / `cell_lattices` / 最新 Anchor leaves / `anchorer_paused` 状态 |

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
| **T6-F-7** ⚠ | **Hub fanout vs peer mesh dual federation**. Detect target Space's `space_writer_model`: hub Space goes through `actor PrincipalServer A → host PrincipalServer B → host_endorsement → fanout` (this server is host or follower); peer_mesh Space keeps existing peer-mesh + RFC 9421 transcript. Cross-deployment hub Space requires actor-side server to forward unsigned-by-host event to host endpoint, host signs endorsement, fans out. | `src/routing/federation.rs`, new `src/routing/federation_hub.rs` | spec Phase 4 §2.4; root C10.B |
| **T6-F-8** ⚠ | **Host endorsement issuance service** (when this soland is the Space Host). Validate incoming actor-signed event (capability + auth_refs + policy), append `host_endorsement` proof signed with this server's service DID, write through to local store, fanout to followers. Concurrency: prevent host fork by serializing per-Space-slot acceptance. | new `src/host_endorser.rs`, `src/routing/federation_hub.rs` | spec Phase 4 §3.3; T2-14 |
| **T6-F-9** ⚠ | **Host transfer ceremony** (smooth dual-sign / emergency governance-quorum). `cx.space.host.transfer.activation_frontier` switches endorsement key. Reducer rejects post-frontier events endorsed by old host. Emergency mode requires `payload.governance_quorum_proof.signers` to be majority of `Space.owning_organizations`. | `src/reducer/kinds/space_host_transfer.rs`, `src/host_endorser.rs` | spec Phase 4 §13; T2-14 |
| **T6-F-10** ⚠ | **§9.5 host fault diagnostic**. Hub Space concurrent-fork on the same state slot → quarantine entire slot, emit host fault report (event refs / HLC / detecting service DID). Trigger emergency transfer candidate condition after `Space.space_host.activation_timeout_ms` of host inactivity or unresolved host fault. | `src/reducer/registry.rs`, `src/host_endorser.rs` | spec Phase 4 §9.5 |

### MIMI

| # | Task | Files | Notes |
| --- | --- | --- | --- |
| **T6-M-1** | MIMI `room_update / notify / room_message` ingest into `cx.*` events instead of audit log; remove demo "alice" mapping. | `src/routing/mimi.rs` | C7 |
| **T6-M-2** | MIMI `consent_request / consent_update` via Tier-3 consent state machine + persistence. Maps to `cx.consent.grant` / `cx.consent.revoke` (spec Phase 5); preserve `consent_id` as inter-protocol correlation. See T2-16. | same | C8; spec Phase 5 §7 |
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

## Spec Phase 1-5 rollout changelog

- **2026-05-07** — **T2-1 spec M-01 wire-name collapse**：`ProjectionEventRecord` 上的 `event_type / input_event_type / canonical_event_type` 三元组合并成单一 `event_kind: String`。Wire 输出（`projection_event_json` / `space.rs` snapshot export / `device.rs` pairing-authorized envelope）只发 `event_kind`；SQL 读路径在 `load_projected_events_from_pg` 中通过 `SELECT event_type AS event_kind` 兼容现有 DB 列名（DB 列重命名作为单独的 Diesel migration tracked 在 "DB schema follow-up"）。`push_outbound.rs` 的 `pointer("/delivery/event_type")` 旧 fallback 一并删除。Test 端三处 assertion 更新（`tests/http_api.rs:1972 / 3109 / 4923`），其中 backfill assertion 加上对 legacy key 缺失的负向断言锁定。`aad_ambiguous_kind` 错误码代码库内确认零命中（spec M-01 同步项已经在更早的清理中移除）。84/84 lib tests + 全部 test binary 编译干净。
- **2026-05-07** — **T1-2 kinds_impl 拆分到 per-domain 文件**：将 760 LOC 的 `src/reducer/kinds_impl.rs` 删除，新建 `src/reducer/kinds/` 目录共 13 个 per-domain 文件（`mod.rs` 持有 4 个共享 `macro_rules!` 宏 + `pub mod` 子模块声明 + 测试；其余 12 个文件按 spec 域分组：messages/reactions/read_marker/entity/relation/container/membership/space_lifecycle/member_state/space_facets/space_inheritance/space_host/consent）。47 个 `ReducerKind` impl 平摊到这些文件，平均每文件 3-4 个 impl。`mod.rs` 的宏通过 `macro_rules!` 文本作用域规则被子模块自动继承，不需要 `pub(crate) use` 重导出。`src/reducer.rs` 收尾两处：`pub mod kinds_impl;` → `pub mod kinds;`，并把 `use crate::{hlc::ServerHlc, kinds};` 中冲突的 `kinds` 移除（旧 use 引入了 `crate::kinds`，与新 `crate::reducer::kinds` 同名冲突），同时把 reducer.rs 内部 `kinds::CX_MEMBERSHIP_*` 全部限定为 `crate::kinds::CX_MEMBERSHIP_*`。`src/reducer/registry.rs` 的 `use crate::reducer::kinds_impl::*;` 改为 `use crate::reducer::kinds::*;`。同步修复 `tests/http_api.rs:5283-5286` `dummy_proof()` 中 T2-11 SDK W6 字段补丁的 `Proof { ... }` 早闭合 syntax bug（`},` 多余、`host_did/endorsed_at` 在结构体外）。`cargo test --lib` 84/84 通过；全部 test binary 编译干净。解锁后续：T1-3 现在可以以"per-kind PR 移出 stub 文件 + 写 project body"的形式渐进推进。
- **2026-05-07** — **T1-1 ReducerKind trait + Registry 落地**（同时完成 T1-5/T1-6/T1-7）：
  - 新增 `src/reducer/registry.rs`：`trait ReducerKind` + `ReducerRegistry` + `StateCardinality`/`Criticality`/`ComponentDescriptor`/`ReducerKindError` 类型；`ReducerRegistry::project()` 是分发入口（subject 派生 → `project()` 调用）。
  - 新增 `src/reducer/kinds_impl.rs`：47 个 ReducerKind 实现（26 active projecting + 21 Phase 1-5 stub）。每个 impl 是 ZST + trait impl，平均 8 行，通过 `singleton_state_kind!` / `non_state_kind!` / `legacy_membership_kind!` / `consent_kind!` 等宏批量生成。
  - `ProjectionState::apply()` 从 ~30 行 match arm 变成 1 行 `registry().project(operation, self, hlc)`；旧 match dispatch 全部撤掉，行为通过 trait dispatch 等价复现。
  - `OnceLock` 缓存全局 registry instance，避免每次调用重建 `BTreeMap`。
  - 主键模型严格遵循 spec Phase 1：`StateCardinality::Singleton/PerSubject/None`；per_subject kind 的 `subject_for_event()` 直接读取 typed payload field（`payload.parent_space_id` / `payload.transfer_id` / `payload.consent_id` / `payload.actor_id` / `payload.member` 等），**禁止** payload 携带 `state_key` 字段（写入这种字段会被 `assert_no_legacy_state_key` 拒绝）。
  - Component metadata 完整下挂：每个 ReducerKind 报告 `component_type` / `component_version` / `criticality`。Paired kinds（`cx.consent.grant`/`revoke`、`cx.capability.grant`/`revoke`）通过共享 `component_type` 表达 slot aliasing。
  - 7 个新 trait/registry 单元测试 + 1 个 dispatcher 测试；现有 reducer behaviour test 全部通过（`message_revise_creates_chain` / `redaction_hides_message` / `reaction_or_set_convergence` / `membership_join_leave` / `legacy_task_move_requires_migration_profile` / `canonical_field_position_move_updates_entity_position_fields` 等等价行为复现）。
  - `cargo test --lib` 84/84 通过（77 原有 + 7 新加）。
  - 解锁后续：T1-2 (per-file split)、T1-3 (project bodies)、T2-13~T2-19 (host endorsement / consent gate / MLS state binding 紧化) 都可以基于这个 trait 直接展开，不需要再做接口设计。
- **2026-05-07** — SDK 完成"彻底移除旧 state_key 模型"清理（移除 deprecated alias + 重命名 ResolvedStateEvent.state_key→subject / state_key_for_event→subject_for_event / state_map_key→state_slot_key）后，本仓同步收尾：
  - 移除 `src/ids.rs` 中 `state_key_segment_encode` / `state_key_compose` 两个 deprecated alias + 对应 test；canonical 名是 `subject_segment_encode` / `subject_compose`
  - `src/routing/directory.rs` stripped_state JSON 输出从 `"state_key": ""` 改为 `"subject": ""`（singleton 状态槽显式标注，非 wire envelope 字段）
  - `src/routing/projection.rs` SQL 列名 `state_key` 暂保留 + comment 标注（DB 列名重命名是 Tier-0 follow-up 迁移工作；存储的值已经是 spec-correct subject）
  - `cargo test --lib` 仍 77 通过（少 1 是因为移除了 `deprecated_state_key_aliases_still_resolve` 测试）
- **2026-05-07** — SDK W1-W11 升级到位（contrix-rust-sdk 端 state-res / Proof / Space / consent / space_host typed model 全部落地，workspace 530+ tests 通过）后，本仓首轮跟进：
  - T2-11 `ids.rs` rename + 8 处 `Proof { ... }` 补齐 `host_did: None, endorsed_at: None` 字段；deprecated alias 已在第二轮清理移除
  - T2-12 旧聚合 kind 确认零命中（soland reducer 尚未实现 `cx.space.policy.set` / `cx.space.lifecycle.set`，无清理工作量）
  - `cargo check --lib` + `cargo test --lib` 全绿（78 tests）
  - 剩余 T2-13~T2-19（writer_model 字段、host_endorsement 验证、host transfer reducer、`cx.consent.*` reducer、invite gate、MLS application_state_ref 紧化）等待 T1-1 ReducerKind trait 设计就位后并行展开；T1-1 必须按新主键模型 `(space_id, kind, subject?)` 一次到位（spec 强制约束）

## DB schema follow-up

- **`space_state_events.state_key` 列重命名**（Tier-0 migration）：spec Phase 1 改名后，DB 列仍叫 `state_key` 是历史遗留。需要 Diesel migration 加一个 column rename + `src/schema.rs` 重新生成；预计 1 个 PR 范围内可独立完成，不阻塞其它工作。

## Quick status (2026-05-08)

- **Code**: `src/` ~28K LOC; `tests/http_api.rs` 5.2K LOC / 42 tests.
- **C10.B 进展**: MAL-0/2/4 已落地 (2026-05-08)。soland 接 SDK 0.2.0；`AppState` 持四 Memory store + CellRegistry；`POST /api/v1/moves` + `POST /api/v1/anchors` 走 SDK 流水线。86 lib tests + 3 new (move_anchor) 通过。
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
