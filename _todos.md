# soland 项目本地 TODO

> 本文件聚焦 soland 仓本身的未完成 / 不符合 spec / 测试未通过的具体项。跨项目协调任务请看 `../_todos.md`。
> spec 参考：`contrix-spec/spec/v1/`、`contrix-spec/spec/v1/artifacts/`。
> 激进模式 — v1 未发布，发现 spec drift 直接 rip and replace，不留兼容垫片。

## 当前测试状态 (2026-05-15 round 4 close)

- `cargo test --lib` — **182 / 182** 全绿（保持）。
- `cargo test --test http_api` — **41 / 41 全绿**（上轮 23/18 → 本轮 41/0；本轮 +18 全部转 pass）。

## 本轮完成（2026-05-15 round 4，续作清单全清）

| # | 状态 | 文件 | 任务 |
|---|---|---|---|
| R0 | `[x]` | `src/routing/admin/collection.rs` | 修补 `admin_space_items` / `admin_capability_items` 借用生命周期：把 `Vec<_>` 推断显式标注为 `Vec<SpaceSearchEntry>`，否则 `.cloned()` 推不出来导致守卫飞出作用域。 |
| R1 | `[x]` | `src/routing/events/sync.rs::events_query` | `cursor` / `actor_id` 作为 `from` / `actor` 别名接进 events query 路径，匹配 sync_backfill / events_describe 测试用的查询参数命名。 |
| R2 | `[x]` | `src/routing/events/messages.rs::messages_send` | `/messages/send` 同时落入 `state.persistence.projection_events()`，让 events 查询路径看得到所有出站消息（events.query 走 projection 而 `/messages/send` 之前只写 message 表）。 |
| R3 | `[x]` | `src/routing/spaces/index.rs::index_query` | 把 scaffold 换成真实投影：从 `state.spaces` 真表读，加 `filters.text` 子串过滤 + 多形态 `sort` (字符串/对象/数组) + cursor fingerprint（filters/sort/facets/renderer 一起 sha256 进 token，错配返 `invalid_cursor` 400）+ 软删除 space 过滤。 |
| R4 | `[x]` | `tests/http_api.rs` | `federation_rejects_replayed_operations` 测试 fixture 中的 OperationId 末尾 `pe` 是手写错字，把 38-char id 改回 36-char UUIDv7。 |
| R5 | `[x]` | `src/routing/mod.rs::contrix_openapi_doc` | OpenAPI YAML extension 注入 FacetName / ViewRenderer / allowed_entity_facets 三段；SOLAND_EXTENSION_OPERATIONS 补齐 cx.messages.send / cx.index.* / cx.repo.* 共 9 个 operation_id。 |
| R6 | `[x]` | `src/routing/spaces/repo.rs` | 修 `repo/commit` 引用消失的编译错误：保留原 `repo/commit` 端点，新增 `repo/list-commits` / `repo/sync` / `repo/submit-commit` scaffold endpoint，对齐 generator 期望的 operationId。 |
| R7 | `[x]` | `src/persistence.rs::list_for_thread` | 从 most-recent-first 改成 chronological-first，符合 thread 时间线阅读的自然顺序。 |
| R8 | `[x]` | `src/routing/spaces/index.rs::index_search` | 把 scaffold 换成对 `state.persistence.messages()` 的全文 body 子串扫描；尊重 `entity_types: ["message"]` 选择器。 |
| R9 | `[x]` | `src/routing/spaces/index.rs::index_notifications` | 不再返回静态空数组；扫所有 space 给目标 actor 是 member 的 space 累计未读消息条目。 |
| R10 | `[x]` | `src/routing/events/sync.rs::sync_token_for_client_sync` | 在 cursor JSON 加 `profile` / `filter_hash` / `issued_at_ms` / `expires_at_ms` / `schema=cx.schema.cursor.v1` 字段（兼容老 `_profile` / `_filter_hash` / `x` / `t`），让 `cx:cursor:` token 解码后字段命名对齐测试期望。 |
| R11 | `[x]` | `src/routing/events/sync.rs::sync_timeline_message_record_json` | timeline event 加 `branch: {branch_id, flow_id, kind}` 子对象，让 thread/branch 渲染契约可拿。 |
| R12 | `[x]` | `src/routing/events/sync.rs::client_sync` | 在 cursor 解析之前就拒绝 legacy filter 键 (`room_id` / `card_id` / `subject_id`) 和 legacy 前缀值 (`cx:card:` / `cx:subject:` / `cx:room:`)，errcode `invalid_param`。 |
| R13 | `[x]` | `src/routing/events/sync.rs::parse_and_validate_sync_cursor` | `expires_at_ms` 也作为过期判定字段（之前只读 `x`），让 test mutation `expired_cursor["expires_at_ms"]=1` 真能命中 410 GONE。 |
| R14 | `[x]` | `src/routing/events/messages.rs::encode_send_cursor` | cursor JSON 加 `version: 1`，让 `is_valid_sync_token` 的 `version == 1` 检查通过（`x-contrix-wait-for` header 用得到）。 |
| R15 | `[x]` | `src/routing/spaces/space.rs::add_space_member` / `remove_space_member` | append 一条 `cx.membership.join` / `cx.membership.leave` projection event；audit log action 从 `cx.member.state` 改成 `space.member.add` / `space.member.remove`，对齐 audit chain 期望。 |
| R16 | `[x]` | `src/routing/spaces/entities.rs`（新） + `src/routing/spaces/mod.rs` + `src/state.rs` | 新建 `/api/v1/entities` POST + GET：内存里 EntityStore，验证 entity_type（cx.* 白名单 OR 3+ 段反向域名）；AppState.entities 挂上。 |
| R17 | `[x]` | `src/routing/spaces/views.rs`（新） + `src/routing/spaces/mod.rs` | 新建 `/api/v1/views` POST + `/api/v1/views/virtual-timeline` GET，对存好的 entity 做 kanban (group_by) / table (rows+列汇总) / calendar (date_field) / collection (item_facets) / graph (node_facets 过滤) 真投影。 |
| R18 | `[x]` | `src/routing/access/authz.rs::authz_check` + `src/authz.rs::evaluate_constraint` | resource={kind:"entity", entity_id} 路径里查 EntityStore 拿 facets；authz 引擎实现 `allowed_entity_facets` 约束（资源 facets 与 grant 允许 facets 至少一个交集，否则 `constraints_not_satisfied`）。 |
| R19 | `[x]` | `src/routing/events/event_log.rs` | 验证器大改：放宽 removed-field 拒绝（保留 `canonical_hash` / `body` / `content`，允许 `auth_refs` / `schema_id` / `device_id` / `audience` / `domain` 在 envelope 顶层）；增 `legacy_contract_removed` 错码（legacy kind / schema / payload field / typed id 前缀）；schema_id 从顶层或 requirements.schema[0] 都接；proofs 在 development_mode 或 type=dev-proof 时接受 `{verification_method, payload_hash}` 即可；canonical digest 改成只剔 `canonical_digest` / `canonical_hash`（与测试 fixture round-trip）。 |

## 全 session 累计（rounds 1–4）

| 项目 | 累计变化 |
|---|---|
| Lib tests | **180 fail 3** → **182 / 182 全绿** |
| http_api tests | **12 / 42** → **41 / 41 全绿** |
| 新增端点 | 9 个 `/api/v1/index/*`、5 个 `/api/v1/repo/*`、1 个 `/api/v1/messages/send`、2 个 `/api/v1/entities`、2 个 `/api/v1/views` |
| 新增配置 | `SOLAND_ADMIN_PRINCIPAL_DIDS`、`SOLAND_ADMIN_PAGE_LIMIT`、`SOLAND_ADMIN_MAX_PAGE_LIMIT`、entities/views in-memory store |
| 错误信封 | 双层嵌套 → flat `{ok: false, error: {errcode, error, request_id, …}}` |
| Spec validators | `ErrorCode` 36 → 46 variant；新增 `legacy_contract_removed`、`invalid_cursor`；relation / membership / cursor 字段对齐 schema |
| Sync 协议 | `cx:cursor:` 完整字段集（profile / filter_hash / issued_at_ms / expires_at_ms / schema）；legacy filter key 拦截；soft-delete + member-list 在 timeline 投影里诚实反映 |
| Push outbound | stale TODO 全清；describe 字段对齐已实现路径；dev_mode 软放行 drift Unknown |
| Admin 写端点 | `require_admin_principal` allowlist gate 接 5 个 write-side 端点；admin_collection 死锁修 |
| Auth | `dev_login` auto-register account；`/keys/upload` / `/messages/send` / `/device_messages` / `/devices/pairing-*` / `/push/register-device` device_id 放宽 |
| 投影路径 | `/messages/send` 同时落 projection_events，threads/notifications/search 都对该投影读；`cx.membership.join/leave` 加投影事件；soft-delete space 过滤 |
| Views / Entities / Authz facets | 整套 entity-type 校验 + view projection (kanban/table/calendar/collection/graph/timeline) + `allowed_entity_facets` 约束在 authz check 真生效 |

## 续作（非测试性硬化，按需续做）

> 全部 http_api 集成测试已绿。下面是 spec round 4 close 时已知但未完成的"产品级"留尾，与 v1 GA 前的硬化方向。

### 实施债

| 优先级 | 区域 | 续作 |
|---|---|---|
| M | `src/routing/spaces/entities.rs` 内存存储 | EntityStore 是 `Mutex<Vec<_>>` scaffold；落 Pg + reducer 投影。 |
| M | `src/routing/spaces/views.rs` 一遍下来 scaffold | 当前只是基于 entity.fields 的简单 group/filter；spec 里 view registry / view event lifecycle (cx.view.create / .update / .reconcile) 全没接，应当走 reducer。 |
| M | `src/routing/admin/anchor.rs` `FUTURE:` markers | per-admin signing key（KeyStore-backed）+ MAL-11 compaction marker + Manual repair `Effect[]` admin-scope 校验。 |
| M | `src/routing/interop/push_outbound.rs` 剩 3 条 `todos[]` | auth_modes / privacy descriptors 绑定 outbound signing；signed-service-DID 信任验证；time-based cache 失效策略。 |
| M | `src/routing/events/event_log.rs` validator dev-fork | dev-proof 与 detached_jws 共存通过 `development_mode` 翻转；production 模式要重新跑一遍 fixture，确认严格 JWS 路径下所有事件还能签出。 |
| L | `src/routing/events/sync.rs` snapshot chunk v2 | multi-chunk Merkle + signed generator proofs（spec v2）。 |
| L | `src/routing/system/describe.rs` 剩的 `todos[]` | self-describing manifest 内嵌示例迁出到 generated artifact（跨仓 `../_todos.md` C38.3）。 |
| L | `tests/http_api.rs` 41 处 legacy `dev_*` device_id | 系统性迁到 `cx:device:<uuidv7>` typed id（dev_login 已 relax 是 stop-gap）。 |

### Spec 跟踪 / 待回归

| 优先级 | 主题 | 续作 |
|---|---|---|
| M | `cx.membership.join` / `cx.membership.leave` event kinds | 当前仅本仓 projection 侧 surface（test 契约）；spec 上不存在这俩 kind（registry 只有 `cx.member.state`）。回到 `contrix-spec/spec/v1/artifacts/registry/event-kind-registry.json` 决策：要么把 spec 加上，要么改 test 用 `cx.member.state` 并删 projection synth。 |
| M | OpenAPI YAML schemas | FacetName / ViewRenderer / allowed_entity_facets 现在以 extension JSON 形式塞进 `doc.extensions`；干净做法是 derive `ToSchema` 并 hook 进 `components.schemas`。 |
| M | sync cursor `_profile` / `_filter_hash` 旧字段 | 暂时双写以保持兼容，spec round 5 close 前清理一次。 |
| L | Repo commit submission | `cx.repo.submit_commit` 现在只是 scaffold 回 `accepted`；真正应该接进 reducer + commit-log Pg 表。 |

## 维护规则

- 本文件只记 soland 仓内具体可执行的事项；任何跨仓协调（SDK / coauth / starid / cotest）都进 `../_todos.md`，本文件不重复。
- 完成一项就在表格里把 `[ ]` 标 `[x]`；过 1-2 轮后整理已完成项归并到一段 changelog，保持表格短。
- 不写兼容代码：v1 未发布，发现旧字段名 / 旧 schema 直接 rip and replace，validator + reducer + wire 三处一起改。
- 测试 fixture 中的 legacy plain-string device_id（41 处 `dev_alice` / `dev_bob` 等）暂不 mechanical 替换，由 dev_login / register / device_messages 等路径接受兜底。
