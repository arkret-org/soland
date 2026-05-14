# soland 项目本地 TODO

> 本文件聚焦 soland 仓本身的未完成 / 不符合 spec / 测试未通过的具体项。跨项目协调任务请看 `../_todos.md`。
> spec 参考：`contrix-spec/spec/v1/`、`contrix-spec/spec/v1/artifacts/`。
> 激进模式 — v1 未发布，发现 spec drift 直接 rip and replace，不留兼容垫片。

## 当前测试状态 (2026-05-14 baseline)

`cargo test --lib` 之前报 **180 passed / 3 failed**：

- `error::tests::variant_count_matches_registry` — `ErrorCode::ALL.len() = 43`，`contrix_core::error::KNOWN_ERROR_CODES.len() = 46`，soland 漏 3 个 spec 已 land 的 error code variant。
- `error::tests::wire_codes_round_trip` — 同根因（漏 variant → 注册表里那 3 个 wire-form code 在 soland 里没有反向映射）。
- `routing::operation_conformance_tests::builtin_operation_conformance_vectors_cover_registry` — `cx.relation.create` validator 要求 payload 含 `from` / `from_entity_id` / `to` / `to_entity_id`，但 `contrix-spec/spec/v1/artifacts/schemas/relation.schema.json` 把 canonical 字段定义为 `from_ref` / `to_ref`（reducer 已经 accept `from_ref`/`to_ref`，validator 没同步）。

`cargo test --test http_api` 还有 30 个 failure（test scaffolding gap，README 标注为 pre-existing F5/F6；先不在本轮 close，按问题分类后续推进）。

## 本轮要做（直接执行）

| # | 状态 | 文件 | 任务 | 说明 |
|---|---|---|---|---|
| L0 | `[x]` | `src/error.rs` | 补 3 个 spec error code variant | `PolicyCombinationInvalid` / `AnchorerRecoveryMissing` / `UnsupportedLatticeType`：写到 enum + `ALL` 数组 + `as_str()` match + `from_wire` 反向映射；HTTP status 走 `core_error::error_code_http_status` 自动取（SDK 已 land 422 binding）。完成后 `variant_count_matches_registry` + `wire_codes_round_trip` 应转 pass。 |
| L1 | `[x]` | `src/routing/events/operations.rs` | `cx.relation.create` payload 字段对齐 spec | 把 `RELATION_FROM_FIELDS` / `RELATION_TO_FIELDS` 主键改成 `from_ref` / `to_ref`，与 `contrix-spec/spec/v1/artifacts/schemas/relation.schema.json` 的 `required: [..., "from_ref", "to_ref", ...]` 对齐；reducer 已经按 `from_ref` 读取 (`src/reducer.rs:733-742`)，validator 是仅剩的 spec drift 点。完成后 `builtin_operation_conformance_vectors_cover_registry` 应转 pass。 |
| L1.1 | `[x]` | `src/routing/events/operations.rs` | `cx.member.state` membership payload 字段对齐 spec | `contrix-spec/spec/v1/artifacts/schemas/event-payload.schema.json#membership_payload` 用 `actor_id` 作为成员字段，但 soland validator 的 `MEMBER_ACTOR_FIELDS` 只接 `member` / `actor` / `sender`。补 `actor_id` 进 `MEMBER_ACTOR_FIELDS`。L1 修完后 conformance vector 顺位前进到 member_state 才暴露这条 drift。 |
| L2 | `[x]` | (verify) | 跑 `cargo test --lib` 确认 3 个失败转 pass | **结果：183/183 全绿**（180 原本 pass + 3 新 pass）。 |

## 已识别但本轮不动（留后续轮 close）

| # | 文件 / 区域 | 性质 | 说明 |
|---|---|---|---|
| P1 | `tests/http_api.rs` 30 failing tests | 测试 scaffolding gap | README §"OpenAPI snapshot test" 标注为 pre-existing F5/F6；都是 dev-login 路径或 protected endpoint 路径上的 scaffolding 没接齐，与 spec compliance 正交。需要单独一轮设计 fixture / auth helper 重写，不在本次"测试转绿 + spec drift 修"的 scope。 |
| P2 | `src/routing/system/describe.rs` `TODO_LEGACY_SESSION_GRANT_JWT` / `TODO_SOLAND_CHALLENGE` / `webpush:TODO` etc. | describe 文档 placeholder | describe 是 self-describing manifest endpoint，inline 的 example value 用 `TODO_*` 占位是当前手工 maintain 的 doc 缺口，等替换成 generated artifact 后才能真消除。属于"生成器对齐"任务，与 ../_todos.md C38.3 同根。 |
| P3 | `src/routing/interop/push_outbound.rs` 一堆 `TODO(push-outbound):` | push outbound bridge 全 scaffold | 整个 push outbound bridge 还是 scaffold（durable snapshot store / etag freshness / contract-drift fail-closed / signed-service-DID trust 全没接），属于 ../_todos.md Stream-F-8 大块工作；要 PostgreSQL 持久化 + 真 HTTP fetch + cache 一起做，不是本轮目标。 |
| P4 | `src/routing/admin/anchor.rs` `TODO(stream_h_admin)` | admin anchor 真 service signer 没接 | replace `service_admin_signer` placeholder with real `MoveSigner` + `is_compaction` 路径 + MAL-11 compaction job 跑通。需要 anchorer 子系统配合，跨 reducer/anchorer 边界，单独立项。 |
| P5 | `src/routing/admin/cells.rs` paging cfg / `src/routing/admin/collection.rs` capability-scoped snapshot API | admin 内部 P1 hardening | `AppConfig` 没 surface admin-cell paging 设置；`/api/v1/admin/{resource}` 还是 dev-only snapshot，没换 capability-scoped 真 API。 |
| P6 | `src/routing/events/sync.rs` P0/P1 sync TODO | sync 高层 P0 工作 | (1) `cx:cursor:` 空间 position 映射到 reducer event；(2) single JSON chunk 换成 deterministic 增量 snapshot。Sync 是 hot path，需要 cursor schema + projection store 一起改，单独一轮。 |

## 维护规则

- 本文件只记 soland 仓内具体可执行的事项；任何跨仓协调（SDK / coauth / starid / cotest）都进 `../_todos.md`，本文件不重复。
- 完成一项就在表格里把 `[ ]` 标 `[x]`；过 1-2 轮后整理已完成项归并到一段 changelog，保持表格短。
- 不写兼容代码：v1 未发布，发现旧字段名 / 旧 schema 直接 rip and replace，validator + reducer + wire 三处一起改。
