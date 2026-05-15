# soland 项目本地 TODO

> 本文件聚焦 soland 仓本身的未完成 / 不符合 spec / 测试未通过的具体项。跨项目协调任务请看 `../_todos.md`。
> spec 参考：`contrix-spec/spec/v1/`、`contrix-spec/spec/v1/artifacts/`。
> 激进模式 — v1 未发布，发现 spec drift 直接 rip and replace，不留兼容垫片。

## 当前测试状态 (2026-05-15 round 11 close — Place projection state + state-machine guards)

- `cargo test --lib` — **187 / 187** 全绿(round 10 baseline 184 + round 11 新增 3 条 Place projection / preflight tests)。
- `cargo test --test http_api` — **40 / 40** 全绿,无退化。
- `cargo test --test move_anchor_wire` — **28 / 28** 全绿。
- `cargo test --test openapi_typed` — **1 / 1** 全绿。
- `cargo build` — **0 warning**。

## Round 10：Place lifecycle 收敛（cx.place.restore + 同族 archive/tombstone)

跟随 `contrix-spec` 新增的 `cx.place.restore`(已在 contrix-rust-sdk PLACE_RESTORE / OP_PLACE_RESTORE 解锁)。当前 soland 对所有 Place lifecycle event 处于"opaque envelope 透传"状态——`kinds.rs::canonical_registered_kind` 不认识 `cx.place.*`,因此 `projection_operation_from_event` 返回 `None`,事件绕开 `validate_operation_semantics`,直接落盘但不投影,reducer 也没分支。这对 `cx.relation.*` / `cx.view.*` 是已实现的模式,但 Place 整族缺失。

**本轮范围**:把 `cx.place.archive` / `cx.place.restore` / `cx.place.tombstone` 三个共享 `place_id`-only payload 的 lifecycle 兄弟接入 canonical-kind 注册表 + 操作 schema validator,与 `cx.relation.update | delete` 同档:envelope 通过 validator(payload 必须含 `place_id`)、落盘、推到 `apply_via_lattice_registry`(后者目前 unknown kind 时仅 trace,不阻塞)。**不**做 Place projection 全量 state-machine —— 那需要 `ProjectionState` 加 Place state map,范围更大,留 round 11+。

服务端不强制 `place_not_archived` 状态机:那条 spec MUST 在 SDK reducer(`crates/sdk/src/resolver/state.rs::restore_place`)层已实现;每个客户端 reducer 自验。soland 这一层负责的是 wire 形态合法 + 持久化 + 派发——与 relation / view 当前承担的责任对称。

| 优先级 | 任务 | 处置 |
|---|---|---|
| H | [x] **R10-1** `src/kinds.rs` 新增 `CX_PLACE_ARCHIVE` / `CX_PLACE_RESTORE` / `CX_PLACE_TOMBSTONE` 常量 | 按字母序插入。 |
| H | [x] **R10-2** `canonical_registered_kind` 加入 Place lifecycle 分支 | 三者都返回 `Some(<kind>)`。 |
| H | [x] **R10-3** 新增 `is_place_lifecycle_kind` 辅助 + 对外导出 | 与 `is_space_lifecycle_kind` / `is_membership_kind` 同款,后续 projection 分流可用。 |
| H | [x] **R10-4** `src/routing/events/operations.rs` 新增 `PLACE_LIFECYCLE_REQUIREMENTS` + 在 `operation_schema_for_kind` 加入 Place lifecycle 分支 | requirements 只要求 `place_id`,与 `cx.relation.update | delete` 的 `RELATION_ID_REQUIREMENTS` 同形;`validate` 字段为 `None`(没有额外正文校验)。**附加**:`src/routing/mod.rs::operation_conformance_tests` 新增 4 条 vector(archive / restore / tombstone happy + restore-missing-place_id 负向),`builtin_operation_conformance_vectors_cover_registry` 测试通过。 |
| H | [x] **R10-5** `cargo build` 通过、`cargo test --lib` 全绿 | 184 / 184 测试全绿(包含本轮新增 4 条 vector);0 new warnings。 |
| M | [x] **R10-6** `cargo test --test http_api` 验 envelope 处理回归 | 40 / 40 全绿,无退化;`move_anchor_wire` 28 / 28、`openapi_typed` 1 / 1 也都全绿。 |

### 范围外(放 round 11+ 或独立 PR)

- **Place projection state(server-side state machine)** — 加 `ProjectionState::places: BTreeMap<PlaceId, PlaceState>`,在 reducer apply 时维护 `active / archived / tombstoned`,然后 `cx.place.restore` 入口校验当前 state == archived,否则返回 412 `place_not_archived`。需要 schema migration(`projection_places` 表)、reducer apply 分支、HTTP error 映射。代价较大,独立 PR。
- **`cx.place.create` / `cx.place.update` / `cx.place.parent` 也走 validator** — create payload 是完整 Place object(`object` 字段),update 是 `place_id` + `patch`,parent 是 `place_id` + `parent_ref`。不像 archive/restore/tombstone 共享同一个 payload shape,所以分开做更干净。同上,独立 PR。
- **Flow / Morph lifecycle 同样未接入** — `cx.flow.create / update / archive / restore / move / reorder` 与 `cx.morph.*` 整族在 soland 都是 opaque-envelope 透传。一并补的话工作量翻倍,目前 yougen / 客户端走 SDK reducer 已经能拿到 state machine,server-side 只缺 wire validator。同步处理时与 Place 同款。
- **Capability check 的精细化** — 当前 event submission path 没有 inline capability action 校验(`cx.place.restore` action 在 `contrix-spec` capability-action-registry 已注册,但 soland 没消费)。整个 Place / Flow / Morph 的 capability 接入也是独立工作。

## Round 11：Place projection state + state-machine guards(2026-05-15)

跟着 contrix-spec 这一轮加的 `common-fields.md §5.1` canonical state-transition table,把 Place lifecycle 整组(`cx.place.create / update / parent / archive / restore / tombstone`)在服务端真正 project 起来,并在 `event_log::submit_event` 加 server-side preflight,把非法状态转换在持久化前就用 HTTP 412 拒掉(spec reason_code:`place_not_active` / `place_not_archived` / `place_already_terminal`)。Round 10 把这 3 个 lifecycle event 接进了 wire validator 但只验 envelope shape;round 11 把状态机真接进 projection / admission。

**本轮交付的完整链路**

| 优先级 | 任务 | 处置 |
|---|---|---|
| H | [x] **R11-1** SQL migration `migrations/20260515000000_place_projection/{up,down}.sql` | `CREATE TABLE projection_places(place_id, space_id, kind, title, parent_ref, rank, state CHECK IN ('active','archived','tombstoned'), state_changed_at, created_*, updated_*)` + 3 个索引(space / state / parent)。 |
| H | [x] **R11-2** `src/schema.rs` 加 `diesel::table! projection_places` + 进 `allow_tables_to_appear_in_same_query!` 列表。 | 字段与 SQL 一一对应。 |
| H | [x] **R11-3** `src/kinds.rs` 把 `CX_PLACE_CREATE` / `CX_PLACE_UPDATE` / `CX_PLACE_PARENT` 也加入 canonical registry。 | 与 round 10 的 archive/restore/tombstone 同档。 |
| H | [x] **R11-4** `src/routing/events/operations.rs` 加 3 个新 requirements 数组(`PLACE_CREATE_REQUIREMENTS`=object、`PLACE_UPDATE_REQUIREMENTS`=place_id+patch、`PLACE_PARENT_REQUIREMENTS`=place_id+parent_ref)+ `operation_schema_for_kind` arm。 |  |
| H | [x] **R11-5** `src/reducer.rs::ProjectionState` 加 `pub places: BTreeMap<String, PlaceProjection>` + `PlaceProjection` struct + `PlaceLifecycleState` enum(Active/Archived/Tombstoned)。 |  |
| H | [x] **R11-6** `ProjectionEffect` 加 `PlaceLifecycle { place_id, new_state }` + `Rejected { reason }` 两个 variant。`PlaceLifecycleTransition` enum 私有,用来在 archive/restore/tombstone 三条路径间共享 guard 逻辑。 |  |
| H | [x] **R11-7** `apply()` dispatcher 加 6 个 Place arm:`CX_PLACE_CREATE → apply_place_create`、`CX_PLACE_UPDATE → apply_place_update`、`CX_PLACE_PARENT → apply_place_parent`、`CX_PLACE_ARCHIVE/RESTORE/TOMBSTONE → apply_place_lifecycle(Archive/Restore/Tombstone)`。 |  |
| H | [x] **R11-8** `apply_place_create` 从 payload `object` 字段抽 id/kind/title/parent_ref/rank/space_id/created_by,插入 `places` map,状态默认 Active。`apply_place_update` / `apply_place_parent` 都做 "current state == Active" 校验,失败返 `Rejected { reason: "place_not_active" }`。`apply_place_lifecycle` 按 spec 表逐 transition 校验,失败返 spec reason_code。所有 helper 对 unknown place 返 `Ignored`(causal/backfill 容忍)。 |  |
| H | [x] **R11-9** `pub fn check_place_lifecycle_transition(&self, &Operation) -> Result<(), &'static str>` —— 只读 preflight 助手,不改 projection。用于 `event_log::submit_event` 在 persist 前判定。 |  |
| H | [x] **R11-10** `event_log::submit_event` 在 `validate_operation_policy` 后、`store.put` 前加一段 preflight:取 `state.projection.lock()`,调 `check_place_lifecycle_transition`,失败时 `render_error(StatusCode::PRECONDITION_FAILED, reason, reason)` 直接返 412 不进 store。 | spec failed_precondition → HTTP 412 直接 path。 |
| H | [x] **R11-11** 三条新单测在 `reducer::tests`:`place_lifecycle_round_trip`(create → archive → restore → tombstone 完整状态机)、`place_lifecycle_preflight_rejects_illegal_transitions`(restore-on-Active / re-archive / restore-on-Tombstoned / tombstone-on-Tombstoned / update-on-Tombstoned 全部正确返 reason_code)、`place_lifecycle_preflight_tolerates_unknown_place`(causal 容忍)。 |  |
| H | [x] **R11-12** `cargo build` / `cargo test --lib` / http_api / move_anchor_wire / openapi_typed 全绿。 | 187 + 40 + 28 + 1 = 256 tests pass,0 warnings。 |

### 范围外(round 12+ 候选)

- **Pg persistence for projection_places** — 当前 round 11 只动了 in-memory `BTreeMap` 与 SQL schema 定义,reducer 内部还没在 apply 时写 `projection_places` 表。下个 round 加 `PgPlaceProjectionStore` impl 把 apply 写穿透到 DB,启动时 hydrate。架构对齐已经 ready(schema.rs 字段都对的上)。
- **Flow / Morph projection state + server-side guards** — Place 这套架构可以直接复用,只是字段不同。等 SDK 加 archive/tombstone 源状态校验(SDK round 10 候选)之后做。
- **Capability check at submit_event for cx.place.\*** — 当前 admission path 没 inline capability check;`cx.place.restore` capability action 已在 contrix-spec 注册,但 soland 不消费。下个 round 加。

## 续作（round 12：候选）

Round 9 / 10 / 11 都已落地。后续候选:

| 优先级 | 主题 | 处置 |
|---|---|---|
| M | Pg-backed `projection_places` | 见 round 11 范围外。schema 已就绪,差 `PgPlaceProjectionStore` impl + reducer write-through + startup hydrate。 |
| M | Pg-backed `projection_events` | 独立 migration：`projection_events` trait 已经准备好，只缺一份 SQL schema + `PgProjectionEventStore` impl。 |
| M | Flow / Morph projection state machine | round 11 给 Place 做了一遍,Flow / Morph 同款。等 SDK round 10 落了再做。 |
| M | MAL-11 prune walk 自动化 | 当前 `anchor-dag/prune` 只支持显式 `{anchor_id}` 调用；后台 worker 周期性遍历 DAG 跑 `CompactionPolicy::is_eligible` 也可以做，但要先有运营痛点。 |
| L | OpenAPI 完整 `ToSchema` 化 | salvo-oapi 自动派生覆盖更多 wire 类型；机械工作。 |
| L | Snapshot v2 multi-chunk fixture | 当前 B4 跑的是 single-chunk case；构造一个大于 256 KiB 的测试 space 来真的走 audit_path 非空路径。 |

## 维护规则

- 本文件只记 soland 仓内具体可执行的事项；任何跨仓协调（SDK / coauth / starid / cotest）都进 `../_todos.md`，本文件不重复。
- 完成一项就在表格里把 `[ ]` 标 `[x]`；过 1-2 轮后整理已完成项归并到 git log，保持表格短。
- 不写兼容代码：v1 未发布，发现旧字段名 / 旧 schema 直接 rip and replace，validator + reducer + wire 三处一起改。
- spec-divergent typed-id 前缀和 event kinds 优先在本仓处理（rename 是单方面动作）；只在影响 spec 注册表本身时进 `../_todos.md`。
- 历史变更（哪轮删了哪个概念、哪轮哪个 prefix 改了名）查 `git log` — **不要**在本文件里维护"deleted things"列表，避免下一轮 agent 误以为还要做。
