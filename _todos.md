# soland 项目本地 TODO

> 本文件聚焦 soland 仓本身的未完成 / 不符合 spec / 测试未通过的具体项。跨项目协调任务请看 `../_todos.md`。
> spec 参考：`contrix-spec/spec/v1/`、`contrix-spec/spec/v1/artifacts/`。
> 激进模式 — v1 未发布，发现 spec drift 直接 rip and replace，不留兼容垫片。

## 当前测试状态 (2026-05-16 round 13 close — Flow / Morph projection state machine)

- `cargo test --lib` — **193 / 193** 全绿(round 12 baseline 187 + round 13 新增 6 条 Flow/Morph projection / preflight tests:`flow_lifecycle_round_trip`、`flow_lifecycle_preflight_rejects_illegal_transitions`、`flow_lifecycle_preflight_tolerates_unknown_flow`、对应 3 条 morph)。
- `cargo test --test http_api` — **42 / 42** 全绿(round 13 新增 `flow_morph_lifecycle_state_machine_returns_412_for_illegal_transitions`,覆盖 Flow + Morph 完整 wire path:create → restore-on-Active(412)→ archive → archive-again(412)→ update-on-Archived(412)→ restore,morph 同款;同时修正 `events_describe_and_single_event_submit_work` 用 cx.flow.create payload 现在必须含 `object` 字段)。
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
| H | [x] **R11-12** wire-level 集成测试 `tests/http_api.rs::place_lifecycle_state_machine_returns_412_for_illegal_transitions`:走真 `POST /api/v1/events` 提交 envelope,验 happy path(create / archive / restore / tombstone 各 200)+ 三处 412(restore-on-Active、tombstone-on-Tombstoned、restore-on-Tombstoned),`body["error"]["errcode"]` 匹配 spec reason_code。引入了一个 helper `signed_place_event` 镜像现有 `signed_event_envelope` 但允许自定义 kind/payload。 |  |
| H | [x] **R11-13** `cargo build` / `cargo test --lib` / http_api / move_anchor_wire / openapi_typed 全绿。 | 187 + 41 + 28 + 1 = 257 tests pass,0 warnings。 |

### 范围外(round 12+ 候选)

- **Pg persistence for projection_places** — 当前 round 11 只动了 in-memory `BTreeMap` 与 SQL schema 定义,reducer 内部还没在 apply 时写 `projection_places` 表。下个 round 加 `PgPlaceProjectionStore` impl 把 apply 写穿透到 DB,启动时 hydrate。架构对齐已经 ready(schema.rs 字段都对的上)。
- **Flow / Morph projection state + server-side guards** — Place 这套架构可以直接复用,只是字段不同。等 SDK 加 archive/tombstone 源状态校验(SDK round 10 候选)之后做。
- **Capability check at submit_event for cx.place.\*** — 当前 admission path 没 inline capability check;`cx.place.restore` capability action 已在 contrix-spec 注册,但 soland 不消费。下个 round 加。

## Round 13：Flow / Morph projection state machine(2026-05-16)

Round 11 给 Place 做了完整 server-side state machine 后,Flow / Morph 整族(SDK round 9/10 已经在 SDK reducer 层补齐了状态机 guard)在 soland 这一层还是 "opaque envelope" 透传。本轮把它们升到与 Place 同档:canonical-kind 注册 + operation schema validator + `ProjectionState` state map + reducer apply 分支 + state-machine preflight + HTTP 412 wire 映射 + unit/integration tests。**与 Place 唯一的结构差异**:spec event-kind 注册表里 `cx.flow.*` / `cx.morph.*` 都**没有** `tombstone` event(终态走 `cx.redaction`),所以 lifecycle dispatcher 只覆盖 archive / restore 两条路径。Terminal 状态 (`deleted` / `redacted`) 在状态机里仍然存在(因为 cx.redaction 可以把对象推到那里),但本轮不实现 redaction 入口——独立 round 处理。

**SDK 配套**:本轮先把 SDK round 10 落了(`contrix-rust-sdk/_todos.md` round 10:archive_flow / archive_morph / archive_place 加 source-state guard、tombstone_place 加 terminal guard、update_flow / update_morph / update_place 加 non-active reject;SDK CHANGELOG Unreleased 顶部已记录,SDK lib +8 条新 resolver 测试全绿)。然后 soland 端镜像。

| 优先级 | 任务 | 处置 |
|---|---|---|
| H | [x] **R13-1** SDK round 10:`crates/sdk/src/resolver/state.rs` 加 archive/tombstone/update 源状态守卫,8 条新测试,_todos.md + CHANGELOG 收尾 | 已落地,684 → 692 SDK tests(contrix=342,新增 8 条 round-10 guard tests)。 |
| H | [x] **R13-2** `src/kinds.rs` 加 `CX_FLOW_CREATE/UPDATE/ARCHIVE/RESTORE`、`CX_MORPH_CREATE/UPDATE/ARCHIVE/RESTORE` 常量;canonical registry 接入;新增 `is_flow_lifecycle_kind` / `is_morph_lifecycle_kind` 助手 | move/reorder/track.* 不在本轮范围(留 round 14)。 |
| H | [x] **R13-3** `src/routing/events/operations.rs` 加 6 个新 requirements(`FLOW_CREATE/UPDATE/LIFECYCLE`、`MORPH_CREATE/UPDATE/LIFECYCLE`)+ `operation_schema_for_kind` dispatcher 加 Flow/Morph arms;`routing/mod.rs::operation_conformance_tests` 加 10 条 vector(8 positive + 2 negative) | `builtin_operation_conformance_vectors_cover_registry` 全绿。 |
| H | [x] **R13-4** SQL migration `migrations/20260516000000_flow_morph_projection/{up,down}.sql` 创建 `projection_flows` / `projection_morphs` 双表,state CHECK IN `('active','archived','deleted','redacted')`(注:不同于 Place 的 `'tombstoned'`);3+3 索引(space / state / morph_type) | `src/schema.rs` 同步加两个 `diesel::table!` 块。 |
| H | [x] **R13-5** `src/reducer.rs::ProjectionState` 加 `flows: BTreeMap<String, FlowProjection>` + `morphs: BTreeMap<String, MorphProjection>`;`FlowProjection` / `MorphProjection` 字段镜像 Pg 表;新增 `ObjectLifecycleState` enum(Active/Archived/Deleted/Redacted,`is_terminal()` 返 `Deleted | Redacted`),Flow / Morph 共用(spec §5.1 同款) | Place 仍用 `PlaceLifecycleState`(独立 Tombstoned 终态)。 |
| H | [x] **R13-6** `ProjectionEffect` 加 `FlowLifecycle { flow_id, new_state }` / `MorphLifecycle { morph_id, new_state }` variants;`ObjectLifecycleTransition` enum 私有(只 Archive / Restore)用于在两条路径间共享 guard 逻辑 | Reuse `Rejected { reason }` variant from round 11。 |
| H | [x] **R13-7** `apply()` dispatcher 加 8 个 Flow/Morph arm:`CX_FLOW_CREATE → apply_flow_create`、`CX_FLOW_UPDATE → apply_flow_update`、`CX_FLOW_ARCHIVE/RESTORE → apply_flow_lifecycle(Archive/Restore)`,morph 4 个同款 | dispatcher 总分支数从 ~25 增加到 ~33。 |
| H | [x] **R13-8** `apply_flow_create` 从 payload `object` 抽 id/title/summary/space_id/created_by,插 `flows` map 状态 Active;`apply_flow_update` / `apply_flow_lifecycle` 各做 spec §5.1 state-machine 校验;morph 三个 helper 镜像 | 所有 helper 对 unknown object 返 `Ignored`(causal 容忍)。 |
| H | [x] **R13-9** `pub fn check_flow_lifecycle_transition` / `pub fn check_morph_lifecycle_transition` 只读 preflight,return `Result<(), &'static str>` 给 event_log 用 | 两个 helper 各覆盖 create(unconditional)+ update/archive(active source)+ restore(archived source)。 |
| H | [x] **R13-10** `event_log::submit_event` preflight 段从单调 `check_place_lifecycle_transition` 扩展为依次 check Place / Flow / Morph;任一失败立刻 `render_error(StatusCode::PRECONDITION_FAILED, reason, reason)` 返 412 | spec failed_precondition → HTTP 412 直接 path,与 Place 同档。 |
| H | [x] **R13-11** `reducer::tests` 新增 6 条 Flow/Morph 单测:`flow_lifecycle_round_trip`、`flow_lifecycle_preflight_rejects_illegal_transitions`(restore-on-Active / re-archive / update-on-Archived 三件)、`flow_lifecycle_preflight_tolerates_unknown_flow`,morph 3 个同款 |  |
| H | [x] **R13-12** `tests/http_api.rs::flow_morph_lifecycle_state_machine_returns_412_for_illegal_transitions`:走真 `POST /api/v1/events` 提交 envelope,覆盖 Flow / Morph 各自的 happy path(create / archive / restore)+ 5 处 412(flow_not_archived / flow_not_active ×2 / morph_not_archived / morph_not_active);新增 `signed_flow_event` / `signed_morph_event` helper | Regression fix:`events_describe_and_single_event_submit_work` 用 `cx.flow.create` 必须现在带 `object` 字段(round 13 之前透传)。 |
| H | [x] **R13-13** `cargo build` / `cargo test --lib`(193 / 193)/ http_api(42 / 42)/ move_anchor_wire(28 / 28)/ openapi_typed(1 / 1)全绿 | 总 264 tests pass,0 warnings。 |

### 范围外(round 14+ 候选)

- **`cx.flow.move` / `cx.flow.reorder` 接入** — 这两个事件不影响 state machine(都是 position-only),但目前还是 opaque envelope。加 canonical registry + operation requirements 即可,无需 reducer state machine 改动。
- **`cx.flow.track.*` 接入** — 4 个 track 子事件(disable/enable/set_primary/update)是 Flow 内部嵌套结构,需要先在 reducer 加 `FlowProjection::tracks` 字段。范围较大独立处理。
- **`cx.redaction` 对 Flow / Morph 状态机的影响** — spec §5.1 说 redaction 会把对象推到 `redacted` 终态;当前 soland 的 `apply_redaction` 只处理 message 路径,没消费 Flow / Morph 的 redaction 目标。下一轮加。
- **Pg persistence for projection_flows / projection_morphs** — schema 已就绪,reducer apply 时还没 write-through 到 DB;同 Place 的 round 12 候选,独立 round。

## 续作（round 14：候选）

Round 9 / 10 / 11 / 12 / 13 都已落地。后续候选:

| 优先级 | 主题 | 处置 |
|---|---|---|
| M | Pg-backed `projection_places` / `projection_flows` / `projection_morphs` | 三张表 schema 都就绪,差 `PgPlaceProjectionStore` / `PgFlowProjectionStore` / `PgMorphProjectionStore` impl + reducer write-through + startup hydrate。 |
| M | Pg-backed `projection_events` | 独立 migration:`projection_events` trait 已经准备好,只缺一份 SQL schema + `PgProjectionEventStore` impl。 |
| M | `cx.flow.move` / `cx.flow.reorder` / `cx.flow.track.*` 接入 | 见 round 13 范围外。track.* 需要 reducer state 加 tracks 字段。 |
| M | `cx.redaction` 对 Flow / Morph 状态机的影响 | 见 round 13 范围外。 |
| M | MAL-11 prune walk 自动化 | 当前 `anchor-dag/prune` 只支持显式 `{anchor_id}` 调用;后台 worker 周期性遍历 DAG 跑 `CompactionPolicy::is_eligible` 也可以做,但要先有运营痛点。 |
| L | OpenAPI 完整 `ToSchema` 化(remaining) | 2026-05-15 round 12 第一遍为 `FederationAnchorsResponse` / `FederationAnchorsPushRequest` / `FederationAnchorsPushResponse` / `EmbeddedWebvhRegisterRequest` 加了 derive。剩余工作:把对应 handler 转 typed signature(`JsonResult<T>` / `JsonBody<T>`),`tests/openapi_typed.rs` forward-compat guard 翻成 positive assertion。继续 grep `&mut Response` + `req.parse_json` 找下一批 untyped handler 候选。 |
| L | Snapshot v2 multi-chunk fixture | 当前 B4 跑的是 single-chunk case;构造一个大于 256 KiB 的测试 space 来真的走 audit_path 非空路径。 |

## 维护规则

- 本文件只记 soland 仓内具体可执行的事项；任何跨仓协调（SDK / coauth / starid / cotest）都进 `../_todos.md`，本文件不重复。
- 完成一项就在表格里把 `[ ]` 标 `[x]`；过 1-2 轮后整理已完成项归并到 git log，保持表格短。
- 不写兼容代码：v1 未发布，发现旧字段名 / 旧 schema 直接 rip and replace，validator + reducer + wire 三处一起改。
- spec-divergent typed-id 前缀和 event kinds 优先在本仓处理（rename 是单方面动作）；只在影响 spec 注册表本身时进 `../_todos.md`。
- 历史变更（哪轮删了哪个概念、哪轮哪个 prefix 改了名）查 `git log` — **不要**在本文件里维护"deleted things"列表，避免下一轮 agent 误以为还要做。
