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
> **2026-05-08 进度**：MAL-0 (旧产物清理，C11 已完成) + MAL-2 (`POST /api/v1/moves` 提交入口) + MAL-4 (`POST /api/v1/anchors` apply_anchor end-to-end) 已落地。AppState 持有 SDK `MemoryMoveStore` / `MemoryAnchorStore` / `MemoryCellStore` / `MemoryCellRegistry`（生产环境可换成 Pg 后端，trait 不变）。
>
> **2026-05-09 进度**：MAL-1 **trait scaffold 已落地** (`BottomPolicy` / `LatticeKindError` / `LatticeKind` trait / `LatticeRegistry` in `src/reducer/registry.rs`，2 个新单测)；47 个旧 stub 重写为 cell_family 实例是后续增量工作。MAL-3 (anchorer 签发 worker) / MAL-5..MAL-15 仍是后续。
>
> **2026-05-09 四轮 激进模式进度**：MAL-1 主体推进 — 新 `src/reducer/lattice_kinds.rs` 35 个真实 impl 覆盖 spec event-kind-registry 全部 cell_family（8 OrSet + 22 CasRegister + 1 Fsm + 5 OrderedLog + 5 MvRegister，详见 MAL-1 子项），`default_lattice_registry()` 工厂 + 10 单测。同时 routing/sync.rs / events.rs 的 `space_id` / `actor_id` / `cursor` 单值 transition fallback 全部清除（aggressive cleanup, no compat — v1 未发布）。lib `88/88 → 98/98` pass。剩余：把 LatticeRegistry 接到 Move/Anchor dispatcher 替代旧 ReducerKind 路径。
>
> **2026-05-09 五轮 激进模式进度**：MAL-1 wiring 主体落地 — `lattice_kinds.rs` 加 `build_sdk_cell_registry()` 工厂将 35 cell families bulk-register 到 SDK `MemoryCellRegistry`；AppState boot 替换 SDK 默认（仅含 ~10 family）为 spec-aligned 的全集；`BottomPolicy::to_sdk_bottom_mode()` 桥接；Membership FSM 用 SDK-canonical 状态名。SDK `state_res` re-export 加 `BottomMode`。新集成测试 `move_on_soland_registered_cell_family_passes_verify` 以 `cx.component.consent.grant.v1`（SDK 默认不识别）add Move 证明 wiring 真实生效。move_anchor_wire `4/4 → 5/5` pass。Move/Anchor pipeline 现在按 spec 而非 SDK 默认子集 resolve cell families。

| # | Task | Files | Notes |
| --- | --- | --- | --- |
| **MAL-0** ⚠ | `[x]` | 旧产物清理：删除 `src/host_endorser.rs`（如已落地）、`src/routing/federation_hub.rs`、reducer kinds 中 `space_host.rs` / `space_host_transfer.rs` stub。回退 ids.rs / wire.rs 中 host_did / endorsed_at / space_writer_model 引用。同步 SDK W6/W7/W8 删除。 | `src/`、`tests/` | 根 C11 |
| **MAL-1** ⚠ | `[x]` | `LatticeKind` trait 替代 `ReducerKind`。**(2026-05-09 六轮 激进模式) 完成核心架构替换**：(a) 35 个真实 LatticeKind impl 覆盖 spec event-kind-registry 全部 cell_family（`src/reducer/lattice_kinds.rs`）；(b) `build_sdk_cell_registry()` 工厂 bulk-register 到 SDK `MemoryCellRegistry`，AppState boot 时使用，让 Move/Anchor pipeline `verify_move` / `apply_anchor` 按 spec resolve；(c) **老 `ReducerKind` trait + `ReducerRegistry` + `src/reducer/kinds/` 13 文件 / 47-stub / 4 macros 全部删除**（净减 ~1248 行，行为等价）；(d) `ProjectionState::apply()` 直接 match-on-canonical-kind 分发到同一组 inline `apply_*` helper（这些 helper 早就存在；trait 只是一层薄包装）。lib `92/92` + move_anchor_wire `5/5` pass。`registry.rs` 现在只承载 `LatticeKind` 相关类型（trait / registry / `BottomPolicy` / `LatticeKindError` / `ComponentDescriptor` / `Criticality` / `StateCardinality`）。 | `src/reducer/registry.rs`, `src/reducer/lattice_kinds.rs`, `src/reducer.rs` | done |
| **MAL-2** ⚠ | `[x]` | Move 提交入口 `POST /api/v1/moves` | `src/routing/move_anchor.rs` | 已落地 (2026-05-08)：`submit_move` 接收 typed `Move`，调 SDK `verify_move` 走 5 步流水线（structural + sig payload_hash + capability placeholder + preconditions + effect-shape via cell registry），通过则 `MoveStore::put_pending`；返回 `{move_id, state: pending\|rejected, reason?}`。**(2026-05-09 十一轮)** JWS 校验从 shape-only 升级到真 Ed25519：`select_jws_verifier(state)` picker 在 `development_mode=true` 用 shape verifier，否则用新 `crate::jws_verify::verify_jws_ed25519` (DID resolver + multibase decode + ed25519-dalek 真验签)。`submit_anchor` / `AnchorerWorker` 也走同一 picker。 |
| **MAL-3** ⚠ | `[~]` | Anchorer 签发 worker (单 DID 模式) | `src/anchorer.rs` (NEW), `src/routing/move_anchor.rs::admin_sign_anchor` | (2026-05-09 七轮) `AnchorerWorker::sign_pending_for_space`: authorization gate (`cx.component.anchorer.v1` cell value 读 + single_did 匹配, genesis 默认 trust service_did) → list_pending → effective_anchor_view 取 pre_state → deterministic_order + verify_move 逐 Move 判 accept/reject → 本地预测 post_state state_root (克隆 cell_store ops + 新 effects → lattice.join → compute_state_root) → 构造 Anchor + 占位 JWS (RFC 7515 §3.2, sha256-derived sig; T7-9 production Ed25519) → 调 apply_anchor 端到端。新 admin 端点 `POST /api/v1/admin/anchors/sign` (op_id `cx.admin.anchors.sign`) 触发一次 signing pass。2 集成测试 (`anchorer_worker_signs_pending_move_and_publishes_anchor` + `anchorer_worker_is_idempotent_when_no_pending_moves`) 端到端 + idempotency 验证；move_anchor_wire `5/5 → 7/7` pass。**剩余**：threshold/open_set/mixed profile (需 leader election + 多签协调)、production Ed25519 (需 DID resolver)、periodic ticker (需 tokio runtime + lease + shutdown)。 |
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
| **MAL-15** | `[~]` | sodmin admin 接口暴露 anchor / lattice 字段 | `src/routing/admin.rs` 或 spaces.rs | `/api/admin/v1/spaces/{id}` 暴露 `anchor_profile` / 当前 anchorer cell value / `cell_lattices` / 最新 Anchor leaves / `anchorer_paused` 状态. **(2026-05-09 二十轮 — Stream H' 解锁) 7 个 admin 端点落地** in `src/routing/anchor_admin.rs`: `GET /api/admin/v1/spaces/{id}/anchorer` (typed `AnchorerValueResponse`，joined cell_value via projection)、`POST .../anchorer/reconfigure` (placeholder Move 构造，`status="placeholder"` + 反 self-sign 校验跳过)、`GET .../bottom` 和 `GET /api/admin/v1/bottom` (扫 ProjectionState::cells 全 `Bottom(_)` 并 snake_case 化 BottomKind)、`POST .../bottom/{cell_id}/repair` (`HeadInWinner|Manual` 内 tag，placeholder Move id)、`GET .../anchor-dag` (live `AnchorStore::list_leaves` + 每 leaf signers/state_root/frontier_union)、`POST .../anchor-dag/compact` (复用 `crate::anchorer::run_one_signing_pass` 触发签发；空 pending 时回填最新 leaf)。Wire DTO 完全镜像 `sodmin/src/types/anchor.rs`（`AnchorerValue / BottomEntry / WinnerHead / BottomRepairStrategy / AnchorDagSnapshot / AnchorLeaf / SubmitMoveResponse / CompactionRequest`），10 个新单测全部通过。剩余 (TODO(stream_h_admin) 锚点)：(1) 真实 reconfig Move 构造 + admin session-grant 签名（需 multi-signer flow）、(2) HeadInWinner / Manual 真实 Move 构造（`head_in` 单 op per spec lattice §5.3）、(3) `is_compaction` 标记（依赖 MAL-11）、(4) `last_compaction_at`、(5) 候选 head 的 issuer / hlc / summary 元数据（需 move_store 二次 lookup）。 |

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

## C19.C + events.subscribe control-frame triggers (2026-05-09 二十轮 激进模式)

- **C19.C ULID audit (clean)**: `grep Ulid|ulid` in `src/` returned only one stale doc comment in `routing/authz.rs:47` (`cx:*:<ulid>` → `cx:*:<uuid>`). 真正的 `Ulid::new()` / `Ulid::from_string` 在 src 中 0 命中（`ids.rs` 早就是纯 `uuid::Uuid::now_v7()`）。
- **C19.C ULID-shape literal cleanup**:
  - `src/routing/describe.rs` 6 处 `cx:space:01JS0SP000000000000000000` / `cx:event:01JS0EV000000000000000000` 替换为 UUIDv7-shape `01904100-0000-7000-8000-000000000000` / `01904101-0000-7000-8000-000000000000`。
  - `src/routing/key_backup_restore.rs` 3 处同样替换。
  - 替换后 `grep '01[A-Z][A-Z0-9]\{23\}'` 在 `src/` + `tests/` 0 命中（确认无 ULID-shape literals 残留）。
- **events.subscribe mid-stream control-frame triggers**:
  - 新 `src/routing/admin_control.rs` (~190 行) 含 2 个 typed `#[endpoint]` handler:
    - `POST /api/v1/admin/events/resync-required` (`cx.admin.events.resync_required`) — broadcast `EventNotificationKind::ResyncRequired { reason }` 到一个 Space 的订阅者，用于 anchor compaction / per-subscriber cursor drift 等场景；clients MUST drop local cache + re-subscribe `from=null`。
    - `POST /api/v1/admin/events/unauthorized` (`cx.admin.events.unauthorized`) — broadcast `EventNotificationKind::Unauthorized { reason }`；clients MUST close stream + re-auth。
  - Request shape `AdminControlFrameRequest { space_id, reason? }` (reason 可选，默认 `"admin_triggered"` / `"session_revoked"`)；response `AdminControlFrameResponse { broadcast, receivers, kind }` 报 broadcast 时的 receiver 计数。
  - Auth gate: 复用 `AuthArgs::authenticated_session`（与 `admin_sign_anchor` / `admin_get_cell` 模式一致）。
  - Wire 端：`routing::sync::events_subscribe` 已经在 `EventNotificationKind::ResyncRequired` / `EventNotificationKind::Unauthorized` 上 dispatch，发出 `kind: "resync_required"` / `"unauthorized"` NDJSON frame；只缺触发器 — 本轮补齐。`Dropped` (broadcast Lagged → `kind: "dropped", reason: "broadcast_lagged"`) 之前就内置在 receive loop。
  - 路由注册：lib.rs 在 `admin/anchors/sign` 后追加两条 (`admin/events/resync-required` + `admin/events/unauthorized`)。
- **Tests** (3 new unit tests in `routing::admin_control::tests`):
  - `resync_required_notification_round_trips_through_channel` — 直接构造 `EventNotification::ResyncRequired` 通过 `tokio::sync::broadcast` channel 验证 round-trip（pin frame shape）。
  - `unauthorized_notification_round_trips_through_channel` — 同上 for `Unauthorized`。
  - `empty_space_id_request_is_caught_at_handler_level` — pin request shape (handler-level `space_id.is_empty()` 校验)。
- **Counts (before → after)**: lib unit tests `131 → 134` (+3 admin_control unit tests). `cargo check --tests` clean (only 1 pre-existing unused-import warning in `jws_verify.rs:352`, not introduced by this turn). `cargo test --lib`: **134/134 pass**.
- **C10.E status**: `GET /api/v1/admin/cells/{cell_id}` 端点 (在 `routing/admin_cells.rs`) 已经在 2026-05-09 十八轮落地并 wired 到 lib.rs；coauth invite consent gate 现在可以直接 HTTP 调用 `principal_server_url + /api/v1/admin/cells/{cell_id}` 查 OrSet `cx.component.consent.grant.v1` cell 状态。本轮无需新增工作。
- **Out-of-scope deferred**:
  - C10.B "把 LatticeRegistry 接到 ProjectionState::apply" 跳过 — 该 path 现在仍走旧 ReducerKind 47-stub trail（实际上 65% 已是真 impl，但 trait 通路还没 swap 到 LatticeKind dispatch；blocking 是 `ProjectionState::apply` 内的 dispatcher 与 `ReducerRegistry` 的耦合）；本轮 scope 中"如果太大可跳过"标的是这一项。
  - Threshold/open_set/mixed anchorer signing path 跳过 — 需要 leader election + 多签协调，不适合单轮直加。

## C10.B 续 — admin cells endpoint (2026-05-09 十八轮 并行)

- **What landed**:
  - 新文件 `src/routing/admin_cells.rs` — 两个 typed `#[endpoint]` handler:
    - `admin_get_cell` (GET /api/v1/admin/cells/{cell_id}) — 读单个 cell 当前 state，返回 `{cell_id, state: "value"|"bottom"|"absent", value?, bottom?, lattice, bottom_policy}`。 family resolves 不到 → 404 (`not_found` envelope)；cell 在 registry 里但从没被写过 → 404 absent。
    - `admin_list_cells` (GET /api/v1/admin/cells?space_id=...&prefix=...&limit=...&offset=...) — `space_id` 必填；`prefix` 按 cell family component 前缀过滤；`limit` 默认 100 / max 1000；分页通过 `offset`。
  - 数据流：路径绕开 SDK 直接读 `state.projection.lock().cells` (Move/Anchor pipeline 的写入端是 `apply_anchor` → `reload_cells_from_store`)；lattice + bottom_mode 通过 `state.cell_registry.resolve(space_id, &cell)` 获得，`LatticeKind::as_wire_str()` 直接做 wire 字符串映射。
  - 路由注册：在 `src/lib.rs` `admin/{resource}` 路由 *之前* 追加两条 (`admin/cells` + `admin/cells/{cell_id}`) 以确保 literal `cells` segment 优先匹配；ADD-only，不动现有行。
  - Auth：复用 `AuthArgs::authenticated_session` pattern (匹配 `admin_sign_anchor`)；缺 Bearer token → 401 canonical envelope；rate limit 走全局 middleware。
  - URL encoding：cell_id 走 path segment，正则只含 `:` + `.` + alnum (URL-path-safe)，receiver 直接 `req.param::<String>("cell_id")` 拿到 decoded 字符串再 `CellRef::new` 严格 round-trip。
- **Why this**:
  - coauth 在 holder principal server 上需要查 `cx:cell:cx.component.consent.grant.v1:<cnt>` 来核 consent grant 状态；sodmin 管理 UI 需要 list bottom-state cells；都缺 public-ish HTTP read endpoint。
  - 该端点是 read-only 切口；写入路径仍只走 Move + Anchor → `apply_anchor` (单一权威)。
- **Tests** (4 unit tests + 6 integration tests):
  - Unit (in `src/routing/admin_cells.rs::tests`): `state_response_value_serializes_with_value_field` / `state_response_absent_state_omits_value_and_bottom` / `resolve_space_extracts_space_subject_when_no_explicit` / `resolve_space_uses_sentinel_for_actor_keyed_cell_when_no_explicit`.
  - Integration (`tests/move_anchor_wire.rs`):
    - `admin_get_cell_on_unknown_cell_returns_404_envelope` — 未写过 cell → 404 + canonical `error.errcode=not_found`。
    - `admin_get_cell_returns_value_after_anchored_move` — Move (invited→join) + admin/anchors/sign → GET cell → `state="value"`, `value="join"`, `lattice="fsm"`, `bottom_policy="reject"`。
    - `admin_list_cells_filters_by_prefix` — 同时存在 member.state + consent.grant 两个 cell；prefix=cx.component.consent. → 只返回 consent.grant，member.state 必须缺席。
    - `admin_get_cell_requires_bearer_token` — 缺 Authorization header → 401 + canonical envelope。
    - `admin_list_cells_requires_space_id_query_param` — 缺 space_id → 400 + `errcode=missing_param`。
    - `admin_list_cells_paginates_with_limit_and_offset` — 两个 cell + limit=1 → cells.len()=1, total≥2, limit=1, offset=0。
- **Counts (before → after)**:
  - lib unit tests: 127 → 131 (+4 admin_cells unit tests)。
  - `cargo test --test move_anchor_wire`: 18 → 24 (+6 integration tests)。
  - Final: `test result: ok. 24 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.59s`。
- **Out-of-scope deferred**:
  - `MAX_LIST_LIMIT` / `DEFAULT_LIST_LIMIT` hard-coded (1000 / 100)；TODO comment notes 应迁到 AppConfig 一次 parallel task B 落地。
  - `space_id` 在 cell registry resolve 用 sentinel scope（actor-keyed cell 没法从 subject 推 space）；待 cell_registry 支持 per-Space scoping 后细化。

## C10.B 续 — DidWebvhResolver chain (2026-05-09 十八轮 并行)

- **What landed**:
  - 新文件 `src/did_resolver_chain.rs` — `pub fn build_did_resolver_chain(&AppConfig) -> CompositeDidResolver` helper. 把以前内联在 `AppState::new` 里的链构造抽出来，按优先级 `DidUuidResolver → DidWebvhResolver (optional) → DidWebResolver → DidKeyResolver` 组装。
  - `src/state.rs` 改动: `AppState::new` 里原本 4-行 inline `CompositeDidResolver::new() + push(DidUuidResolver) + push(DidWebResolver) + push(DidKeyResolver)` 替换成单行 `did_resolver_chain::build_did_resolver_chain(&config)`。Imports 同步从 `{CompositeDidResolver, DidKeyResolver, DidUuidResolver, DidWebResolver}` 收窄到 `CompositeDidResolver` (helper 自己引剩下 3 个)。
  - `did_resolver_chain` 用 `#[path = "did_resolver_chain.rs"] pub mod did_resolver_chain;` 挂在 `state` 模块下而不是 `lib.rs` 顶层 — 因为 parallel task A 当前持有 `lib.rs` 的编辑锁。Re-export 路径是 `crate::state::did_resolver_chain`。
- **Integration with starid**:
  - 配置入口: `SERVERX_STARID_WEBVH_RESOLVER_URL=https://starid.example` (no trailing slash) 通过既有 `AppConfig::starid_webvh_resolver_url: Option<String>` 字段。`Some(_)` 时 helper 把 `DidWebvhResolver::new()` 推入链；`None` (默认) 时跳过。
  - URL shape: starid 在 `<URL>/<scid>/<host>/<path...>/did.json` 提供 `did:webvh` 文档；chain 里的 SDK resolver 是 cache-based (`insert_from_https_response` / `ingest_log`)，production 还需要 fetcher 来填充 cache (后续工作)。当前 chain 落位是 fetcher 接入的前提。
  - **Resolver priority**: `DidWebvhResolver` 排在 `DidWebResolver` 之前，确保 `did:webvh:...` DID 不会 fallthrough 到 `did:web` (`DidWebResolver::supports()` 本身就拒 webvh，但 ordering 把 intent 写死，免得未来引入 fallback 行为时偷偷换语义)。
  - **`did_resolver_allow_methods` 过滤**: helper honor 既有 `AppConfig::did_resolver_allow_methods: Vec<String>` 字段。允许列表包含 `"webvh"` (case-insensitive) 时才推入 webvh resolver；空列表当 "allow all" 处理（向后兼容旧 deployment）。production env CSV 里加 `webvh` 才能启用，跟 spec discovery 端点 `identity_describe` 已宣告的 `cx.identity.starid.webvh.optional.v1` profile 对齐。
- **Tests** (5 新 unit tests in `state::did_resolver_chain::tests`):
  - `chain_includes_webvh_resolver_when_url_configured` — 配置 starid URL → chain `supports(did:webvh:...)` 返 true
  - `chain_omits_webvh_resolver_when_url_absent` — URL=None → chain `supports(did:webvh:...)` 返 false (但 did:web 仍 supported)
  - `chain_priority_puts_webvh_before_web` — well-formed did:webvh DID 触发的错误是 webvh-flavored ("did:webvh document not cached")，证明 dispatch 走 webvh 而不是 web
  - `did_resolver_allow_methods_filter_applies_to_webvh` — allow_methods 不含 "webvh" 时，即使设了 URL chain 也不推 webvh resolver
  - `empty_allow_methods_treated_as_allow_all` — 空 allow list 视作 "全允许"，chain 同时 support webvh + web
- **测试结果**: lib `122 → 131` pass (+5 new + 4 from concurrent十六+十七轮 lands in same window). Build clean (`cargo build --lib` finishes). Integration tests `tests/http_api.rs` / `tests/openapi_typed.rs` 仍因十四+十五轮 添加的 `jws_replay_window_seconds` / `jws_replay_window_per_family` 字段 missing 而 pre-broken (out-of-scope for this round; tracked separately).
- **Out of scope / follow-ups**:
  - `DidWebvhResolver` 是 cache-based — 实际 HTTPS fetch (调用 `insert_from_https_response` + `ingest_log`) 需要单独的 fetcher worker 来定期或 on-demand 拉 starid 的 `did.json` / `did.jsonl`。chain placement 是这个 fetcher 接入的前提。
  - `starid_webvh_resolver_url` 当前只用作 "enable" toggle；多 starid instance 或 `GET /describe` 探活检查留待 fetcher PR 一起做。
  - `routing/identity.rs::identity_describe` 已经 surface 这个 profile，无需改动。

- **2026-05-09 十四+十五轮 并行** — **differentiated replay window + mid-stream control frames**：
  - 用户指示 "没做的能并行, 并行" — 在本轮内同批落地两个相互独立但触及相同文件 (`submit_anchor` / `anchorer.rs`) 的 soland-internal 任务。其他跨项目任务 (C10.D yougen / C10.E coauth / C10.F sodmin) 按 "其他等待下一轮" 推后。
  - **十四轮 — Differentiated replay window per cell-family**:
    - 新 `AppConfig::jws_replay_window_per_family: BTreeMap<&'static str, u64>` 字段（key 必须是 `&'static str` 的 cell_family 名，避免 String allocation per check）。
    - 新 `AppConfig::default_replay_overrides()` 工厂：anchorer.v1=60s / mls.epoch.v1=60s / consent.grant.v1=120s / capability.{grant,delegate,derived}.v1=120s（spec 推荐的 tight 窗口）。
    - 新 `jws_verify::verify_replay_window_for_move(move, default, overrides)` + 暴露的 `effective_window_for_move(move, default, overrides)` helper。算法：
      1. 遍历 `move.effects[]`
      2. 用 `CellId::parse(cell.as_str()).component()` 提取 cell_family
      3. 在 overrides 里 lookup → 找到则更新 `effective`：`if effective == 0 { override } else { effective.min(override) }`
      4. 返回 effective 作为生效 window
    - 特殊语义：default=0 (disable) 但有 override → override 接管。让 dev/test config (window=0) 仍能保护 anchorer cell；如果想全关只能清空 overrides map（`BTreeMap::new()`）。
    - `submit_move` 和 `AnchorerWorker::sign_pending_for_space` 都改用 `verify_replay_window_for_move`。`submit_anchor` 仍用 `verify_replay_window(&anchor.hlc, ...)` 因为 Anchor.hlc 是 anchor 自己的而不是 effects 衍生的。
    - test_config 加 `jws_replay_window_per_family: BTreeMap::new()` 保留旧 fixture 兼容。
    - **6 新 unit tests** in `jws_verify::tests`:
      - `effective_window_picks_default_when_no_overrides_apply`
      - `effective_window_uses_anchorer_override_when_anchorer_cell_touched`
      - `effective_window_takes_minimum_when_default_tighter_than_override`
      - `effective_window_zero_default_with_override_uses_override`
      - `anchorer_cell_with_60s_override_rejects_2min_old_hlc`
      - `message_cell_under_default_300s_accepts_2min_old_hlc`
  - **十五轮 — Mid-stream control frames**:
    - `EventNotification` 改成 enum 包装：`{space_id, kind: EventNotificationKind}` 五变体 (Event / EpochRotation / Frontier / ResyncRequired / Unauthorized)。
    - 旧用法 `EventNotification { space_id, cursor, event_payload }` 改成 `EventNotification::event(space_id, cursor, event_payload)` 工厂。`projection.rs::project_accepted_operations` 同步改名调用。
    - 新工厂 `EventNotification::epoch_rotation(...)` / `::frontier(...)`。
    - `submit_anchor` (`routing/move_anchor.rs`) 和 `AnchorerWorker::sign_pending_for_space` (`anchorer.rs`) 在 `apply_anchor` 成功后：
      1. 在 reload_cells_from_store **前** 捕 `mls.epoch` cell 的旧值
      2. reload (写入新值)
      3. 无条件 broadcast `Frontier { state_root: post_state_root, anchor_id: anchor.id }`
      4. 仅当 prev != new 时 broadcast `EpochRotation { previous_epoch, new_epoch }`
    - `events_subscribe` (`routing/sync.rs`) 在 broadcast `recv` arm 改用 match-on-kind 分发产出 NDJSON：`Event` → `kind=event` (含 seq+cursor+payload)、`EpochRotation` → `kind=epoch_rotation` (含 previous/new_epoch)、`Frontier` → `kind=frontier` (含 state_root+anchor_id)、`ResyncRequired` → `kind=resync_required` (含 reason)、`Unauthorized` → `kind=unauthorized`。
    - `ResyncRequired` / `Unauthorized` 变体的触发器（per-subscriber drift detection / session token 过期）暂未接入，留 placeholder for next round；当前 broadcast 通道触发只发 EpochRotation + Frontier。
    - **1 新集成测试** `anchorer_pass_broadcasts_frontier_frame_to_subscribers`：直接 `state.event_broadcast.subscribe()` (跳过 HTTP subscribe 的 demo-space 注册要求) → 触发 admin/anchors/sign → drain notifications → 找到 `Frontier { anchor_id, state_root }` 验证 anchor_id starts with `cx:anchor:sha256:` + state_root starts with `sha256:`。
  - 测试结果：lib `116/116 → 122/122` + move_anchor_wire `17/17 → 18/18` pass。
  - 剩余 production 工作：subscribe-side `kind=resync_required`/`unauthorized` triggers (需要 per-subscriber state); cell_registry 跨 Space scoping (现 anchorer cell 全局共享，多 Space 部署需要细化)。

- **2026-05-09 十三轮 激进模式** — **space_states 双层迁移 (cells + structured cache)**：
  - 把 ProjectionState `space_states: BTreeMap<String, SpaceState>` 这个最后的 cell-driven structured 字段也改成双层架构，跟 read_receipt_policies / memberships 一致。
  - **结构化 cache 保留**: `space_states` 持续承载 server-side `created_at` / `updated_at` 时间戳 + 简单 `deleted` bool + side-band `owner` / `title` (consumer `routing/index.rs::space_state_count` 仍读这一层)。
  - **Cells map 写入**: `apply_space_lifecycle` 现在按 canonical kind 选目标 cell family:
    - `cx.space.create` → `cx.component.space.create.v1` (ordered-log, singleton): 把 `{owner, title, created_at, operation_id}` append 到现有 `Value::Array` 或初始化新 array
    - `cx.space.update` → `cx.component.space.organization.v1` (cas-register, singleton): 写 `Value::Object {owner?, title?, updated_at}` latest-wins
    - `cx.space.destroy` → `cx.component.space.destroy.v1` (cas-register, singleton): 写 `Value::Object {destroyed: true, at, operation_id}` terminal
  - **Dispatcher 改动**: 之前 `Some(CX_SPACE_CREATE) | Some(CX_SPACE_UPDATE) | Some(CX_SPACE_DESTROY) => apply_space_lifecycle(operation, now)` 把 kind 丢了；改成 `Some(kind @ (CX_SPACE_CREATE | CX_SPACE_UPDATE | CX_SPACE_DESTROY)) => apply_space_lifecycle(operation, now, kind)` 透传到 helper，让它能按 kind 选目标 cell。
  - **新 query helpers**:
    - `space_create_log(space_id) -> Option<&[Value]>` 直接读 ordered-log cell, 返回 entries slice
    - `space_organization_cell_value(space_id) -> Option<&Value>` 通过 `cell_value` (auto-filter Bottom) 返回 latest cas-register value
    - `space_is_destroyed(space_id) -> bool` 检查 destroy.v1 cell 是不是 `Value(_)` (任何非 None / Bottom 都视为 destroyed)
  - **5 新 unit tests** in `reducer::tests`:
    - `space_create_writes_both_structured_cache_and_ordered_log_cell` — 验证 create event 把 owner/title 写到 `space_states[space_id]` AND 把同一信息 append 到 cells.create.v1 ordered-log
    - `space_update_writes_organization_cell_with_cas_register_semantics` — 验证 update event 把 latest owner+title+updated_at 写到 organization cas-register
    - `space_destroy_writes_destroy_cell_and_marks_cache_deleted` — 验证 destroy event 让 `space_is_destroyed()` true 同时 `space_states.deleted = true`
    - `space_create_log_appends_on_repeated_create_events` — 验证 ordered-log 累积不是 latest-wins (与 cas-register 区别)
    - `space_organization_cell_returns_none_for_uncreated_space` — helpers 对未创建空间返 None / false (不 panic)
  - **依赖关系**: 不删 `space_states` field 因为 `routing/index.rs` 仍读它；删除是后续工作（先迁所有 consumers，再删字段）。
  - lib `111/111 → 116/116` pass。
  - **post-十三轮 双层架构总结**:
    - read_receipt_policies (CasRegister) ✅ 删旧字段，纯 cells
    - memberships (FSM) ✅ 双层 (cells + members structured cache)
    - space_states (mixed: ordered-log + cas-register) ✅ 双层 (cells + space_states structured cache)
    - durable-event-only fields (messages / reactions / read_markers / entities / relations / redactions) — spec 无 cell_family 声明，按 spec 应保持 structured 不迁移

- **2026-05-09 十二轮 激进模式** — **JWS replay protection (HLC-window)**：
  - **设计选择**: 用 `Move.hlc`/`Anchor.hlc` 物理时间作为 freshness anchor。这两个字段在 `canonical_bytes_for_id` 内 → 在 JWS 签名负载里 → 攻击者无法在不破坏签名的情况下篡改它们。**对比** `MoveSignature.created_at` 是 envelope 字段但不在签名里，可以被攻击者随意改 — 我们故意不信它。
  - 新 `AppConfig::jws_replay_window_seconds: u64` 字段 (env `SERVERX_JWS_REPLAY_WINDOW_SECONDS`, 默认 300s = 5 分钟。0 = 完全关闭，dev / tests 用)。
  - 新 `pub fn verify_replay_window(hlc: &Hlc, window_seconds: u64) -> Result<(), String>` 在 `src/jws_verify.rs`。+ test-only `verify_replay_window_at(..., now: DateTime<Utc>)` 注入 wall-clock。算法：解析 HLC 12-hex physical-ms 前缀 → `DateTime::from_timestamp_millis` → 计算 delta = now - signed_at → window=300s → if delta > window: "too old" → if -delta > window: "too far in future" → else: Ok。
  - `submit_move` 在 `verify_move` (含 JWS crypto verify) 通过后调用 `verify_replay_window(&move_obj.hlc, ...)` — JWS verify 已经保证 Move.hlc 没被篡改。
  - `submit_anchor` 在 `apply_anchor` 之前先做 `verify_replay_window(&anchor.hlc, ...)` — anchor.hlc 在 anchorer_sig 签名负载里。
  - `AnchorerWorker::sign_pending_for_space` 在 step 5 (deterministic_order + per-Move verify) 中按 Move 检查 replay window — 长期 pending 的 Move 如果 hlc 已老化超过 window 会被 drop 而不是被 anchor 上链。
  - **5 unit tests** in `jws_verify::tests`:
    - `replay_window_zero_seconds_disables_check_for_any_hlc`
    - `replay_window_accepts_hlc_within_bounds`
    - `replay_window_rejects_stale_hlc` (1h 旧)
    - `replay_window_rejects_future_hlc` (1h 未来 — 防 clock-skew 攻击)
    - `replay_window_accepts_hlc_at_exact_boundary` (恰 300s — 边界条件 delta == window 应通过；用 `from_timestamp_millis` 对齐避免 ns 精度漂移)
  - **3 integration tests** in `tests/move_anchor_wire.rs`:
    - `submit_move_rejects_stale_hlc_with_replay_window_reason` — 1h 旧 hlc → state="rejected"，reason 含 `replay_window` + `too old`
    - `submit_move_rejects_future_hlc` — 1h 未来 → reject + `future`
    - `submit_move_accepts_current_hlc_under_replay_window` — now → state="pending"
  - 测试用 `replay_window_test_config()` (window=300, dev_mode=true 保留 dev-login 取 token); 其他既有测试 `test_config()` 用 window=0 保留旧 fixed-time fixture 兼容 (`0189c4d2af00...` = July 2023 hlc，否则全 reject)。
  - **双重防护**: Move.id 是 content-addressed sha256(canonical_bytes) → MoveStore.put_pending 是 idempotent → 相同 Move 重发自然 dedup (即使 hlc 旧也是 idempotent 的 no-op)；hlc-window 防护**截获后短时间内**的 replay 利用窗口。Server restart 后 MoveStore 清空，hlc-window 仍然防护。
  - lib `106/106 → 111/111` + move_anchor_wire `14/14 → 17/17` pass。
  - **剩余**: nonce-based dedup cache (依赖 store-id idempotency 已经够用，spec 不强制) ;不同 cell-family 差异化 window (high-stakes anchorer cell 60s vs messages 5min) — 都是 hardening 不阻塞 production。

- **2026-05-09 十一轮 激进模式** — **T7-9 production Ed25519 JWS verify**：
  - 新模块 `src/jws_verify.rs` (~290 行，6 unit tests) 含 `pub fn verify_jws_ed25519(canonical_bytes, jws, vm, issuer, &state) -> Result<(), String>` 完整 RFC 7515 §3.2/§5.2 verifier:
    1. Detached shape parse (`<header>..<sig>`，3 段，payload 段空，sig 段非空且非 zero-sentinel)
    2. Header b64u decode + alg=EdDSA 检查
    3. Signature b64u decode → 64 字节 → `ed25519_dalek::Signature::from_bytes`
    4. `state.did_resolver.lock().resolve_did(&did)` 解析 verification_method 的 DID 部分
    5. DidDocument.verification_methods 三策略 lookup (full URL / fragment-only / single-key fallback for did:key)
    6. `decode_ed25519_multibase`: z-prefix strip → `bs58::decode` → 0xed 0x01 multicodec varint check → 32 字节 raw key → `VerifyingKey::from_bytes`
    7. RFC 7515 §5.2 signing_input 重组 `BASE64URL(header) || '.' || BASE64URL(canonical_bytes)`
    8. `public_key.verify(signing_input.as_bytes(), &signature)` 真 Ed25519 验签
  - 新 picker `routing::move_anchor::select_jws_verifier(state) -> impl Fn(&[u8],&str,&str,&str) -> Result<(),String> + Copy`：闭包捕 `&AppState`，按 `state.config.development_mode` 在 `verify_jws_shape` (dev) / `verify_jws_ed25519` (prod) 之间分发。`Copy` bound 满足 `apply_anchor`'s `F: Copy` 要求 (因为 `&AppState: Copy`)。
  - `submit_move` / `submit_anchor` / `AnchorerWorker::sign_pending_for_space` 三处都改用 `select_jws_verifier(state)`，硬编码 `verify_jws_shape` 全部清除。
  - 新依赖：`ed25519-dalek = "2.1.1"` + `bs58 = "0.5.1"`。
  - **6 unit tests** (jws_verify::tests):
    - `round_trip_multibase_decode_recovers_public_key`
    - `decode_rejects_wrong_multicodec_prefix` (用 secp256k1 multicodec 0xe7 → 拒绝)
    - `decode_rejects_missing_z_prefix`
    - `parse_detached_jws_accepts_canonical_shape`
    - `parse_detached_jws_rejects_non_empty_payload`
    - `parse_detached_jws_rejects_too_few_segments`
  - **4 integration tests** (move_anchor_wire 直接调 `soland::jws_verify::verify_jws_ed25519`，不走 HTTP — production 配置下 dev-login 关闭，无法取 token):
    - `production_verifier_accepts_real_ed25519_did_key_signature` (deterministic seed [7;32] → SigningKey → encode_ed25519_multibase → did:key URL → 真签名 → 验证通过)
    - `production_verifier_rejects_tampered_signature` (翻 sig 第一字节 → ed25519-dalek `verify_strict` 失败 → reject)
    - `production_verifier_rejects_signature_over_different_payload` (签 payload A 验 payload B → 拒绝，证明 verifier 真绑 canonical_bytes 不只是 shape)
    - `production_verifier_rejects_unknown_verification_method` (did:web:unreachable.example#k1 → resolve 失败 → reject)
  - lib `100/100 → 106/106` + move_anchor_wire `10/10 → 14/14` pass。
  - **生产部署 next steps**: service_did 的 DID Document 需要注册到 starid / DID resolver chain (现在 `did:web:soland.local` 解析需要 HTTP fetch); HW-backed signer (HSM / TPM 集成); JWS replay protection (created_at + nonce window 检查) 是独立的下一步。

- **2026-05-09 十轮 激进模式** — **events.subscribe 改为 NDJSON 长连接流式响应**：
  - **架构**: 新 `tokio::sync::broadcast::Sender<EventNotification>` 字段加到 AppState (capacity 1024)；`EventNotification { space_id, cursor, event_payload }` 类型；`AppState::new` 初始化 `broadcast::channel(1024).0`。
  - **写端**: `routing::projection::project_accepted_operations` 在每个 accepted event 落地后调 `state.event_broadcast.send(...)` 广播；`send` 返回 `Err` 仅当无活跃 receiver — 不是 error path（无人订阅是稳态）。
  - **读端**: `events_subscribe` 重写流式：(1) `subscribe()` 拿 receiver (在序列化历史 frames 前 — 防止漏掉历史与订阅之间到达的事件)，(2) `async_stream::stream!` 异步生成器 yield NDJSON 行 (`Bytes`)，调 `res.stream(stream.boxed())` 让 Salvo 走 `ResBody::Stream` 输出 chunked。
  - **流逻辑**: 历史 frames → `catchup_complete` → tokio::select 循环 (broadcast recv / heartbeat tick / max_duration deadline)：
    - `Ok(notification)` 通过 space_filter set 过滤后 yield `kind=event` frame
    - `Err(RecvError::Lagged(n))` → yield `kind=dropped, skipped=n, reason=broadcast_lagged` (告诉 client 重 sync)
    - `Err(RecvError::Closed)` → break (server shutdown)
    - heartbeat tick → yield `kind=heartbeat, ts=...`
    - deadline 到 → yield `kind=heartbeat, stream_closing=true` 后 break
  - **可调参数**: `max_duration_ms` query param (default 60s, max 600s) + `heartbeat_ms` (default 15s, min 100ms)。
  - **新依赖**: `bytes = "1.10.1"` (Salvo `res.stream` 要 `Into<BytesFrame>`)，`futures-util = "0.3.31"` (`StreamExt::boxed` / Stream combinators)，`async-stream = "0.3.6"` (`stream!` async-generator 宏)。
  - **2 集成测试**:
    - `events_subscribe_streams_live_event_then_closes_at_deadline` — 主路径：spawn writer 协程 wait 150ms 后 POST `/api/v1/messages/send`，`messages/send` 触发 `project_accepted_operations` → broadcast → subscriber 收到 NDJSON `kind=event` frame。验证 frame 顺序 (`catchup_complete` 在前，`event` / `heartbeat` 在后) + content-type `application/x-ndjson`。
    - `events_subscribe_emits_close_heartbeat_at_deadline` — idle 流 deadline 后正常关闭，发出 `stream_closing=true` heartbeat。
  - **测试用 demo space**: 这两个测试用 pre-seeded `cx:space:0196419b-0000-7000-8000-000000000000` (公开 + alice 是 member) 因为 `space_id_accessible` 在 events_subscribe 路径里 enforce；其他 Move/Anchor 测试用不同 space (那条路径不走 access check)。
  - lib `100/100` + move_anchor_wire `8/8 → 10/10` pass。
  - **剩余**: 真生产长连接需要反向代理 buffer 配置 (Nginx `proxy_buffering off` 等) + Salvo connection-keepalive 调参；`epoch_rotation` / `unauthorized` / `resync_required` 等 mid-stream control frames 需要专用触发器（不是 broadcast，是状态变化触发的，比如 anchorer cell 改变 / token 失效 / large lag 检测）。

- **2026-05-09 九轮 激进模式** — **memberships 迁移到 cells + 结构化 cache 双层**：
  - **完整删除** `pub memberships: BTreeMap<String, BTreeMap<String, MembershipState>>` + `pub banned_members: BTreeMap<String, BTreeSet<String>>` + `pub knocking_members: BTreeMap<String, BTreeSet<String>>` 三个旧字段。
  - **替换为单一** `pub members: BTreeMap<(String, String), MembershipState>`（flat keying = (space_id, actor_did)，更清晰）。
  - `MembershipState` 加 `state: String` 字段（镜像 FSM 状态，权威源在 cells map）。
  - `apply_membership` 同时写两层：
    1. `members[(space_id, actor)] = MembershipState { state, role, joined_at, updated_at, ... }` — side-band data + FSM mirror
    2. `cells[cx:cell:cx.component.member.state.v1:<actor>] = CellState::Value(state)` — FSM 权威源
  - FSM 表扩展 (`reducer/lattice_kinds.rs::build_sdk_cell_registry`)：原 5 转换 → 12 转换覆盖完整生命周期：
    - 邀请：invited→{join, leave}
    - 敲门：knock→{join, leave}
    - 已加入：join→{leave, kick, ban}
    - 重入：kick→{invited, knock}, leave→{invited, knock}, ban→invited（unban）
  - 新 query helpers：
    - `members_in_state(space, state) -> Vec<&MembershipState>` — 替代 banned_members BTreeSet 的查询路径（`members_in_state(space, "ban")`）+ knocking_members（`members_in_state(space, "knock")`）
    - `member(space, actor) -> Option<&MembershipState>` — 单 entry 查询
    - `member_fsm_state(actor) -> Option<String>` — 直接读 cells map 拿 FSM 状态（权威源）
    - `members_of_space()` 保留 legacy 语义 (filter `state="join"`) — 行为等价于旧字段（旧字段只在 JOIN event 时插入）
  - `unban` event 现在会把状态 set 成 `invited`（per FSM `ban→invited` 转换），不只是清除 `banned_members`。语义更精准。
  - `routing/index.rs::membership_count` 改用 flat-map filter (`state="join"`)。
  - 3 个新 unit tests：`membership_join_writes_both_structured_cache_and_fsm_cell` / `ban_then_unban_round_trips_through_fsm_states` / `knock_state_visible_in_members_in_state_query`。
  - `routing/projection.rs` membership-related sites: 0 references (内部 `apply_membership` 自动适配；外部消费者只 `routing/index.rs` 一处)。
  - lib `97/97 → 100/100` pass + move_anchor_wire `8/8` pass。
  - **架构成果**：FSM 状态有了 cells map 权威源（cell-keyed），结构化 side-band data 在 `members` cache 里，两层不互斥（`members.state` mirror cell value）。`banned_members` / `knocking_members` 这种"特殊状态额外 BTreeSet" 全部消失 — 通过 `members_in_state` query 派生。
  - 剩余：`space_states` 同样双层迁移 (mixed cell families + title/owner side-band)，本轮没动。

- **2026-05-09 八轮 激进模式** — **ProjectionState::cells map 迁移启动**：
  - **Inventory**：跨 11 个 structured 字段，仅 4 个对应 spec 声明的 `cell_family` (read_receipt_policies / memberships / banned_members / space_states 的部分内容)；其他 6 个 (messages / reactions / read_markers / entities / relations / redactions) 是 durable-event 投影，无 cell_family 声明，按 spec 应保持 structured。
  - 新增 `pub cells: BTreeMap<CellRef, CellState>` 字段到 `ProjectionState` (`src/reducer.rs`)。
  - 新增 accessor `ProjectionState::cell(&CellRef) -> Option<&CellState>` + `cell_value(&CellRef) -> Option<&Value>` (filter Bottom)；helper `read_receipt_policy_cell_value(space_id) -> Option<&Value>` 用于具名 cell 查询。
  - 新方法 `ProjectionState::reload_cells_from_store(space_id, &dyn CellStore, &dyn CellRegistry) -> Result<(), StoreError>` 读 CellStore + lattice.join 写回 cells map。
  - **删除** 旧 `pub read_receipt_policies: BTreeMap<String, ReadReceiptPolicySnapshot>` 字段 + `ReadReceiptPolicySnapshot` struct。
  - `routing::move_anchor::submit_anchor` 在 `apply_anchor` 成功后调用 `proj.reload_cells_from_store(...)` 刷新该 Space 的 cells map。
  - `crate::anchorer::AnchorerWorker::sign_pending_for_space` 同样在 apply_anchor 成功后调用 reload — 让 anchorer 推进的 Anchor 也能立即在 read 路径上看到。
  - `routing::projection::project_read_receipt_policy` (durable-event 路径) 改写：直接 synth 一个 CellState::Value 到 cells map 的对应 CellRef，让 durable-event 与 Move/Anchor 两个写入路径**统一到 cells map 这一个目的地**。
  - `routing::events::effective_read_receipt_policy_for_space` (用于 cx.receipt.read fanout 的 fast-path) 改用 `proj.cell_value(&cell_id)` 查询；durable-event 冷启 fallback 路径保留。
  - 3 个新 unit tests in `reducer::tests`：`cell_value_returns_none_for_unwritten_cell` / `cell_value_returns_none_for_bottom_state` / `read_receipt_policy_cell_value_helper_extracts_canonical_value`；1 个新 integration test `anchorer_pass_populates_projection_cells_map`：完整端到端 (submit Move → trigger anchorer → assert `cells[member_cell] = Value("join")`)。
  - lib `94/94 → 97/97` + move_anchor_wire `7/7 → 8/8` pass。
  - **剩余迁移**: memberships (FSM cell + role/joined_at side-band) / banned_members / knocking_members / space_states (mixed cell families + title side-band) 都需要双层架构 (cells map + structured cache)，本轮没动。durable-event-only 字段 (messages / reactions / read_markers / entities / relations / redactions) 按 spec 应该 stay structured，不迁移。

- **2026-05-09 七轮 激进模式** — **MAL-3 Anchorer 签发 worker 落地** (单 DID 模式)：
  - 新文件 `src/anchorer.rs`：`AnchorerWorker { service_did }` + `sign_pending_for_space(state, space_id, max_moves) -> Result<Option<AnchorerOutcome>, AnchorerError>`，9 步流水线匹配 spec event-auth-state-resolution.md §3-§4：(1) `is_authorized_for` 读 `cx.component.anchorer.v1` cell value（CasRegister，shape="single_did" + did 匹配 service_did，genesis Space 隐式信任 service_did），(2) `MoveStore::list_pending_for_anchorer`，(3) `AnchorStore::list_leaves` + `effective_anchor_view`，(4) `read_effective_state` 拼 pre_state map（重用 SDK lattice resolve + join），(5) `deterministic_order` + `verify_move` 逐 Move 判定，(6) `predict_post_state_root` 本地模拟（克隆现有 ops + 新 effects → per-cell lattice.join → compute_state_root），(7) `Anchor` 构造（predecessor_refs=current leaves, frontier=pred_frontier ∪ accepted moves, state_root=predicted）→ derive_id → 占位 sig 重签 over canonical_bytes_for_id，(8) `apply_anchor` SDK 端到端，(9) 返回 `AnchorerOutcome { anchor_id, accepted_move_ids, rejected_moves, post_state_root }`。
  - 占位 JWS：RFC 7515 §3.2 detached shape (`base64url({"alg":"EdDSA"})..base64url(sha256(canonical_bytes))`)，过 soland `verify_jws_shape`；real Ed25519 是 T7-9 (DID resolver-dependent)。
  - 暴露 `routing::move_anchor::shape_only_jws_verifier_for_anchorer` 让 worker 复用 verify_move/apply_anchor 的同一个 verifier (无重复 JWS 规则)。
  - 新 admin 端点 `POST /api/v1/admin/anchors/sign` (`cx.admin.anchors.sign` op): JsonBody `{ space_id, max_moves? }` → 调 `crate::anchorer::run_one_signing_pass` → `SignAnchorResponse { published, anchor_id?, accepted_move_ids[], rejected_moves[], post_state_root? }`. `NotAuthorized` → 403 `policy_violation`，其他错误 → 409 + reason。
  - 2 集成测试 in `tests/move_anchor_wire.rs`：`anchorer_worker_signs_pending_move_and_publishes_anchor` 端到端（submit Move → POST /admin/anchors/sign → assert published=true + accepted_move_ids 含我们的 Move + post_state_root 等于本地 compute_state_root(member_cell→Value("join")) 预期）；`anchorer_worker_is_idempotent_when_no_pending_moves` 二次 trigger 后 published=false。
  - SDK `state-res` re-export 加 `BottomMode` 让 lattice_kinds.rs 桥接到 `BottomMode` (前几轮已加)。
  - move_anchor_wire `5/5 → 7/7` pass + lib `94/94` pass。
  - **C10.B R2 主体收尾**：Move 提交端到端 closure 现已闭合 — 客户端 POST /api/v1/moves，soland anchorer 自己签出 Anchor 推进 effective_anchor_view，无须客户端手写 Anchor。剩余 deferred 子项：threshold/open_set/mixed profile (需 leader election)、production Ed25519 (T7-9，DID resolver)、periodic ticker (production ops batch)。

- **2026-05-09 六轮 激进模式 (核心架构替换)** — **MAL-1 老 ReducerKind 路径整体删除**：
  - 用户多次喊"激进, 不要兼容"——前几轮的"删除"只动了表层（query-string fallback、`actor_id` 单值参数等）。**双轨架构**（durable Event 路径走 `ReducerKind` / 47 stub trait registry；Move/Anchor 路径走 `LatticeKind` / `LatticeRegistry`）一直没拆。本轮一次性削掉。
  - 删除：`src/reducer/kinds/` 整目录（13 文件 = 4 macros + 12 per-domain ZST 文件 / 共 47 stub structs / 共 ~600 行）；`registry.rs` 中 `ReducerKind` trait（~36 行）+ `ReducerRegistry` struct（~140 行）+ `ReducerKindError` enum（~22 行）+ 3 registry-internal unit tests（`registry_has_unique_kinds` / `registry_includes_post_phase_1_5_kinds` / `registry_rejects_legacy_aggregate_kinds`）；`reducer.rs` 顶部 `OnceLock`-cached `registry()` 函数。
  - 替换：`ProjectionState::apply()` 现在直接 `match crate::kinds::canonical_kind_for_operation(operation)` 分发到 `apply_message` / `apply_redaction` / `apply_reaction_add` / `apply_reaction_remove` / `apply_read_marker` / `apply_entity_*` / `apply_relation_*` / `apply_container_position` / `apply_membership` / `apply_space_lifecycle` 这些 inline helper——它们一直存在；trait + registry 只是包了一层薄分发。`crate::kinds::is_membership_kind` 处理 6 个 cx.membership.* 分支。`CX_LEGACY_TASK_MOVE` 仍要求 `migration_profile` payload 字段。
  - `registry.rs` 现在只保留 `LatticeKind` 相关类型（trait / registry / `BottomPolicy` / `LatticeKindError` / `ComponentDescriptor` / `Criticality` / `StateCardinality`）+ scaffold 单测；纯净 ~290 行（vs 旧 584 行）。
  - 净减 ~1248 行；lib `98/98 → 92/92`（少 6 是 registry-internal 测试）；move_anchor_wire `5/5`；所有 behavior 测试（message_create / redaction / reaction / entity / membership / message_revise / canonical_field_position_move 等）维持绿。
  - 顺带修：SDK schema test `cx:event:<ulid>` → `cx:event:<uuid>` 对齐 spec id-kind-registry.json（pre-existing drift；不在本仓但堵 SDK 测试）。
  - **C10.B MAL-1 收官**：从此 soland 内 ProjectionState driver 单一架构（直接 match dispatch）；Move/Anchor pipeline 单一架构（LatticeKind via SDK MemoryCellRegistry）；不再有"双轨"。剩余 R2 工作：Anchorer 签发 worker（MAL-3）、ProjectionState 结构化字段→单一 cells map（routing/* 30+ handler 联动）。

- **2026-05-09 五轮 激进模式** — **MAL-1 Move/Anchor pipeline 接 LatticeRegistry**：
  - `lattice_kinds.rs` 加 `lattice_bindings_for_sdk_registry()` 工具函数（返回 `(family, sdk_lattice_kind, sdk_bottom_mode)` 三元组列表）+ `build_sdk_cell_registry()` 工厂（bulk-register 全部 35 cell families 到 SDK `MemoryCellRegistry`，FSM 家族用 `register_fsm` 显式声明 transition 表）。
  - `BottomPolicy::to_sdk_bottom_mode()` 桥接到 SDK `state_res::BottomMode` enum。
  - AppState boot (`state.rs:cell_registry`) 替换 `MemoryCellRegistry::new()`（SDK 默认，仅 ~10 family）为 `build_sdk_cell_registry()`，让 Move/Anchor receive pipeline 的 `verify_move` / `apply_anchor` 实际 resolve 全部 spec-declared cell families 的 lattice + bottom_mode。
  - Membership FSM 转换表用 SDK-canonical 状态名（`invited` / `join` / `leave` / `ban`）匹配 wire shape，避免破坏现有 move_anchor_wire 测试中 `transition.from="invited",to="join"` 形态。
  - SDK 端 `crates/state-res/src/lib.rs` re-export 列表加 `BottomMode`，让下游 import path 是 `contrix_sdk::state_res::BottomMode`。
  - 新集成测试 `tests/move_anchor_wire.rs::move_on_soland_registered_cell_family_passes_verify`：构造一个 add Move 写 `cx.component.consent.grant.v1` cell（SDK 默认 `MemoryCellRegistry::default()` 不包含此 family，不替换会以 `unknown cell family` 失败），断言 submit 返回 `state="pending"`，证明 wiring 真实生效。
  - move_anchor_wire `4/4 → 5/5` pass + lib `98/98` pass。**这是 C10.B 真正落地节点**：Move/Anchor pipeline 现在按 spec event-kind-registry 而非 SDK 默认子集 resolve cell families。

- **2026-05-09 四轮 激进模式** — **MAL-1 LatticeKind 35 个真实 impl + transition fallback 清除**：
  - 新文件 `src/reducer/lattice_kinds.rs`：35 个 LatticeKind 真实 impl 覆盖 spec event-kind-registry 全部 cell_family。Macros `singleton_lattice!` (定义 ZST + 自动 trait impl，singleton subject) + `per_subject_lattice!` (同前 + typed subject_for_effect 读 payload 字段并返回 `MissingSubjectField` 错误)。Lattice 选型 100% 跟随 spec：8 OrSet (consent.grant / capability.{grant,delegate,derived} / session.grant / device.{authorized,list_update} / mls.covered_frontier) + 22 CasRegister (space.* 20个 + flow.position + place.parent + anchorer + mls.epoch) + 1 Fsm (member.state) + 5 OrderedLog (space.{create,child,parent} / account.status / policy.rule) + 5 MvRegister (profile.create / view.{create,update,reconcile} / mimi.room_binding, bottom=expose)。
  - `default_lattice_registry()` 工厂函数：一次性注册全部 35 个 impl，downstream Move/Anchor pipeline 在 boot 时调用。
  - 10 单测：注册数量 ≥40、consent.grant lattice + subject 派生、member.state Fsm + actor 派生、space.policy singleton CasRegister、anchorer.v1 singleton CasRegister + Required criticality、covered_frontier singleton OrSet、5 个 MvRegister family bottom=expose 一致性、ordered-log singleton + per-subject 双形态、MissingSubjectField typed 错误显式 surface、未知 family lookup → None。
  - **Aggressive cleanup, no compat (v1 未发布)**: `routing/sync.rs` `events_subscribe` / `events_query` + `routing/events.rs` `events_query_durable_scope_impl` 删除 `space_id` / `actor_id` / `cursor` 单值 transition fallback；clients MUST 用 `spaces=` / `actors=` / `from=` 新名。同步删除 `multi_space_invalid_cursor` 死变量。
  - lib `88/88 → 98/98` pass + move_anchor_wire `4/4` pass，编译 clean (0 warnings)。

- **2026-05-09** — **MAL-1 LatticeKind trait scaffold**：在 `src/reducer/registry.rs` 现有 `ReducerKind` trait 旁追加并行 scaffold，让 C10.B per-cell-family runtime 可以增量落地而不是 big-bang refactor。
  - 新增 `pub enum BottomPolicy { Reject, Expose }`：表达 spec 中 `bottom ∈ {reject | expose}` 的二态语义（默认 Reject，与 cas-register / fsm 等"拒绝并发候选"行为一致）。
  - 新增 `pub enum LatticeKindError`：`MissingSubjectField{cell_family, field}`（spec subject 派生时找不到必需字段）+ `UnknownCellFamily{observed, declared}`（注册表 cell_family 与 effect payload 不匹配）；`Display` 实现稳定，便于日志 / 错误码透传。
  - 新增 `pub trait LatticeKind: Send + Sync`：方法 `cell_family() -> &'static str`、`lattice() -> contrix_sdk::lattice::LatticeKind`（直接复用 SDK enum，避免本仓重复定义）、`bottom_policy() -> BottomPolicy`（默认 Reject）、`component() -> ComponentDescriptor`、`subject_for_effect(&serde_json::Value) -> Result<Option<String>, LatticeKindError>`。
  - 新增 `pub struct LatticeRegistry { families: BTreeMap<&'static str, Box<dyn LatticeKind>> }` + `register / lookup / len / is_empty`。
  - 2 个新单测在 `lattice_kind_scaffold_tests` 模块：`registry_register_and_lookup_works`（注册一个 dummy `OrSet` cell family，lookup 命中 / miss 都验证）+ `lattice_kind_error_display_is_stable`（两个变体的 Display string 锁定）。
  - 与现有 `ReducerKind` trait **共存**：47 个旧 stub 不动，scaffold 不启用任何 dispatch；后续 PR 按 cell_family 一个个写真实 `LatticeKind` impl + 接 SDK lattice crate 真实 `join`，最终把 `ReducerRegistry::project()` 切到 `LatticeRegistry`。
  - `cargo test --lib lattice_kind` 2/2 pass；整体 lib 88/88 + move_anchor_wire 4/4 pass，scaffold 编译干净。

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
