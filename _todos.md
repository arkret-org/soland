# soland 项目本地 TODO

> 本文件聚焦 soland 仓本身的未完成 / 不符合 spec / 测试未通过的具体项。跨项目协调任务请看 `../_todos.md`。
> spec 参考：`contrix-spec/spec/v1/`、`contrix-spec/spec/v1/artifacts/`。
> 激进模式 — v1 未发布，发现 spec drift 直接 rip and replace，不留兼容垫片。

## 当前测试状态 (2026-05-15 此轮结束)

- `cargo test --lib` — **182 / 182**（基线 180/3 → 上轮 183/0 → 本轮 182/0；一条 lib test 在 linter 改 operations.rs 时被去除）。
- `cargo test --test http_api` — **23 passed / 18 failed**（基线 12/30 → 上轮 18/24 → 本轮 23/18，本轮 +5 来自新增 index/repo 端点 scaffold + events_query 接受单数 `space_id` 查询参数）。

## 本轮完成（2026-05-15 round 3）

| # | 状态 | 文件 | 任务 |
|---|---|---|---|
| Q0 | `[x]` | `src/routing/spaces/index.rs`（新） + `src/routing/spaces/mod.rs` | 新建整个 `/api/v1/index/*` scaffold 模块：`describe` / `entity` / `thread` / `notifications` / `inbox` / `search` / `space-hierarchy` / `query` / `debug/reducer` 共 9 个端点。`/index/query` 跑 facet/renderer/sort/cursor 维度的 in-memory 投影，unsupported facet 直接返空集；`/index/debug/reducer` 从 `state.persistence.messages()` 读真实条目算 frontier；`/index/entity` 按 typed id 前缀（`cx:space:` / `cx:flow:` / 等）识别 kind。 |
| Q1 | `[x]` | `src/routing/spaces/repo.rs`（新） + `src/routing/spaces/mod.rs` | 新建 `/api/v1/repo/*` scaffold：`describe`（返 `repo_did` = service_did + `supported_signatures` + `limits`）、`operations`（按 `operation_ids[]` 从 `state.persistence.events()` 拉，未命中放 `missing[]`）。 |
| Q2 | `[x]` | `src/routing/events/sync.rs::events_query` | `GET /api/v1/events?…` 现在同时接受 singular `space_id` / `actor` 别名（之前只接 plural `spaces[]` / `actors[]`），消除测试 fixture 与 handler 之间的查询参数 drift。 |

## 全 session 累计（rounds 1–3）

| 项目 | 状态变化 |
|---|---|
| Lib tests | **180 fail 3** → **182 / 182 全绿** |
| http_api tests | **12 / 42** → **23 / 41**（+11 转 pass；one test removed by linter cleanup） |
| 新增产品配置 | `SOLAND_ADMIN_PRINCIPAL_DIDS`（admin allowlist）、`SOLAND_ADMIN_PAGE_LIMIT` / `SOLAND_ADMIN_MAX_PAGE_LIMIT`（admin pagination） |
| 新增端点 scaffold | 9 个 `/api/v1/index/*`、2 个 `/api/v1/repo/*` |
| 错误信封 | 双层嵌套 → flat Matrix/Palpo 形（`body.error.errcode` / `body.error.error`） |
| Spec validators | `ErrorCode` 36 → 46 variant；relation `from_ref`/`to_ref`、membership `actor_id` 对齐 schema |
| Sync cursor | `cx:cursor:` token 翻译进 backfill event-id cursor |
| Push outbound docs | 一轮 stale-TODO 清理 + describe 字段对齐已实现路径 |
| Admin write-side 端点 | 5 处 `require_admin_principal` gate 接进去 |

## 续作（这轮没合上；按需续做）

剩 18 个 http_api fail，按所需工作量聚类：

### 缺端点 / 实质功能 — 真"产品级"实现

| 优先级 | 测试 | 缺什么 |
|---|---|---|
| L | `account_contacts_and_space_lifecycle_workflow` | 全流程：register account → contact request → 接受 → 创建 space → 邀请 → 加入 → 删除。要 contact lifecycle reducer。 |
| L | `auth_keys_device_messages_and_blobs_work` | 链式：keys/upload → keys/query → device_messages send → blob upload → blob get + access check。要补齐多个端点的实际行为。 |
| L | `revoked_device_blocks_encrypted_writes` | 设备 revoke 后还要 enforce 在 events submit 的 proof 校验里。 |
| L | `keys_query_hides_revoked_device` | 同上：device revoke 状态要 mask 掉 keys/query 输出。 |
| L | `view_endpoints_project_common_presentation_shapes` | 整个 `/api/v1/views`（kanban / table / calendar / collection / graph projection）+ `/api/v1/views/virtual-timeline` + `/api/v1/entities` lifecycle。这是真的视图引擎。 |
| L | `standard_entity_types_and_reverse_domain_custom_types_work` | `/api/v1/entities` POST + GET，多 entity_type 校验、`cx.channel` 等标准类型。 |
| L | `push_profile_and_moderation_contracts_work` | `/api/v1/push/rules` + `/api/v1/push/rules/mute-device` + `/api/v1/moderation/report` flows。 |
| L | `device_pairing_challenge_and_authorization_surface_work` | `/api/v1/devices/pairing-challenge` + `/authorize-pairing`。 |
| L | `schema_registry_contracts_work` | `/api/v1/schemas/{schema_id}` upsert + GET round-trip with versioning。 |
| L | `index_query_supports_structured_filters_sort_and_cursor` | 跟 Q0 同模块但要实跑跨 Space 真投影 + 排序 + cursor 一致性，scaffold 不够。 |
| L | `index_reducer_debug_reports_projection_frontier` | `/api/v1/messages/send` 缺端点（test 先发消息再校 frontier）。 |

### Sync / 协议路径上的 spec 细节

| 优先级 | 测试 | 缺什么 |
|---|---|---|
| M | `sync_backfill_exposes_prev_batch_and_limited_timeline_pages` | `prev_batch` / `limited` 字段在某些 path 上缺失或语义不对。 |
| M | `to_device_messages_survive_duplicate_sync_until_cursor_ack` | to_device messages cursor ack 持久化语义。 |
| M | `device_messages_evicted_after_session_logout` | logout 时 evict 该 session 所有 to_device message。 |
| M | `server_preserves_e2ee_payloads_as_opaque_data` | E2EE envelope 字段 server-side preserve 不动语义。 |
| M | `federation_rejects_replayed_operations` | federation txn 重放 detection（按 `(origin, txn_id)` digest）。 |
| M | `events_describe_and_single_event_submit_work` | describe 的某个字段断言；submit_event 行为细节。 |

### Wire 校对 / generator

| 优先级 | 测试 | 缺什么 |
|---|---|---|
| M | `contrix_openapi_spec_contains_facet_projection_contracts` | OpenAPI snapshot test — facet projection 相关 operation_id 在 generated openapi 里。 |
| M | `admin_collection_surfaces_return_sodmin_shapes` | admin collection 输出字段与 sodmin DTO 对齐。 |

### 非 http_api 但 _todos.md 历史列入

| 优先级 | 区域 | 续作 |
|---|---|---|
| M | `src/routing/admin/anchor.rs` `FUTURE:` markers | per-admin signing key（KeyStore-backed）+ MAL-11 compaction marker + Manual repair `Effect[]` admin-scope 校验。 |
| M | `src/routing/interop/push_outbound.rs` 剩 3 条 `todos[]` | auth_modes/privacy descriptors 绑定 outbound signing；signed-service-DID 信任验证；time-based cache 失效策略。 |
| L | `src/routing/events/sync.rs` snapshot chunk v2 | multi-chunk Merkle + signed generator proofs（spec v2）。 |
| L | `src/routing/system/describe.rs` 剩的 `todos[]` | self-describing manifest 内嵌示例迁出到 generated artifact（跨仓 ../_todos.md C38.3）。 |
| L | `tests/http_api.rs` 41 处 legacy `dev_*` device_id | 系统性迁到 `cx:device:<uuidv7>` typed id。dev_login 这边已 relax，下一步是 test fixture mechanical 替换 + 让 dev_login 自动 mint typed id。 |

## 维护规则

- 本文件只记 soland 仓内具体可执行的事项；任何跨仓协调（SDK / coauth / starid / cotest）都进 `../_todos.md`，本文件不重复。
- 完成一项就在表格里把 `[ ]` 标 `[x]`；过 1-2 轮后整理已完成项归并到一段 changelog，保持表格短。
- 不写兼容代码：v1 未发布，发现旧字段名 / 旧 schema 直接 rip and replace，validator + reducer + wire 三处一起改。
- 测试 fixture 中的 legacy plain-string device_id（41 处 `dev_alice` / `dev_bob` 等）暂不 mechanical 替换，由 dev_login 路径接受兜底。
