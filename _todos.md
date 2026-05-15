# soland 项目本地 TODO

> 本文件聚焦 soland 仓本身的未完成 / 不符合 spec / 测试未通过的具体项。跨项目协调任务请看 `../_todos.md`。
> spec 参考：`contrix-spec/spec/v1/`、`contrix-spec/spec/v1/artifacts/`。
> 激进模式 — v1 未发布，发现 spec drift 直接 rip and replace，不留兼容垫片。

## 当前测试状态 (2026-05-15 round 6 close)

- `cargo test --lib` — **184 / 184** 全绿（保持）。
- `cargo test --test http_api` — **39 / 39 全绿**（round 5 是 41/41；round 6 删除 2 个 entity/view 测试因为它们考察一个不在 spec v1 的抽象层）。
- `cargo test --test move_anchor_wire` — **14 passed / 14 failed**（同主分支基线，pre-existing；未引入回归）。

## 本轮完成（2026-05-15 round 6：entity/view 概念清理）

`entity` / `entity_type` / `entities` / `cx:entity:*` / `cx.entity.*` / `cx.entities.*` 在 `contrix-spec/spec/v1/artifacts/` 里完全不存在。spec 用具体 typed-id 前缀（`cx:flow:`、`cx:place:`、`cx:morph:`、`cx:relation:`、`cx:view:`、`cx:actor_profile:` 等），每种各有专门的 event kind（`cx.flow.create` / `cx.morph.create` / …）。这一轮把 soland-local 的 entity scaffold 全部抹除。

| # | 状态 | 文件 | 任务 |
|---|---|---|---|
| T0 | `[x]` | 删除 `src/routing/spaces/entities.rs` / `src/routing/spaces/views.rs` | 整文件删除，scaffold 不留。 |
| T1 | `[x]` | `src/routing/spaces/mod.rs` | router 拓扑里抹掉 `entities::router()` / `views::router()` 与 mod declaration。 |
| T2 | `[x]` | `src/state.rs` | `EntityRecord` struct 删除。 |
| T3 | `[x]` | `src/persistence.rs` | `EntityStore` trait + `MemoryEntityStore` impl + `entities()` accessor + Pg fallback delegate 全删。 |
| T4 | `[x]` | `src/routing/system/util.rs` | `is_valid_entity_type` + `is_supported_cx_entity_type` 删除（保留 placeholder 注释说明历史）。 |
| T5 | `[x]` | `src/kinds.rs` | `CX_ENTITY_CREATE` / `CX_ENTITY_UPDATE` / `CX_ENTITY_DELETE` 常量 + `canonical_registered_kind` 三个 match 分支删除。 |
| T6 | `[x]` | `src/routing/events/operations.rs` | `ENTITY_ID_FIELDS` / `ENTITY_TYPE_FIELDS` / `ENTITY_CREATE_REQUIREMENTS` / `ENTITY_ID_REQUIREMENTS` + `validate_entity_create_operation_payload` + `cx.entity.*` / `cx.field.position.*` schema entries 全删；`from_entity_id` / `to_entity_id` 字段别名也清掉；mention type `entity` 改成 `flow`（指向 `cx:flow:*` typed id）。 |
| T7 | `[x]` | `src/wire.rs` | DTO 删除：`CreateEntityRequest` / `EntityResponse` / `UpdateEntityRequest` / `ListEntitiesRequest` / `CreateViewRequest` / `ViewResponse` / `IndexEntityResponse` / `FacetName` enum / `ViewRenderer` enum / `AllowedEntityFacetsConstraint`。`IndexQueryRequest.entity_types` / `IndexSearchRequest.entity_types` 重命名为 `object_kinds`。 |
| T8 | `[x]` | `src/routing/mod.rs::contrix_openapi_doc` | `add_schema` 三连（FacetName/ViewRenderer/AllowedEntityFacetsConstraint）删；x-contrix-artifacts 里 `view_constraint_kinds: ["allowed_entity_facets"]` → `authz_constraint_kinds: ["allowed_object_facets"]`；删除 `use ToSchema` import。 |
| T9 | `[x]` | `src/authz.rs::evaluate_constraint` | `allowed_entity_facets` → `allowed_object_facets` 重命名；错误信息一并改。 |
| T10 | `[x]` | `src/routing/access/authz.rs::authz_check` | 删除 `entity:*` 资源 wildcard 分支 + `entity_id` 查 EntityStore facets 的代码块；保留通用 facets 从 resource 对象取的路径。 |
| T11 | `[x]` | `src/routing/spaces/index.rs` | `/api/v1/index/entity?entity_id=` 改名 `/api/v1/index/object?object_id=`；`index_entity` → `index_object`；`entity_kind_for` → `object_kind_for`（多接一个 `cx:relation:` prefix）；响应字段 `entity: {entity_id, …}` → `object: {object_id, …}`。`entity_types[]` 在 index_search 改成 `object_kinds[]`（无 fallback alias，rip-and-replace）；results 里 `entity_id` 改为 `object_id`。 |
| T12 | `[x]` | `src/reducer/lattice_kinds.rs` + `src/reducer/registry.rs` | 测试断言 + 注释里 `cx.entity.update` 删除。 |
| T13 | `[x]` | `tests/http_api.rs` | 删除两个针对 entity/view 抽象的测试（`standard_entity_types_and_reverse_domain_custom_types_work` / `view_endpoints_project_common_presentation_shapes`）；改写 `account_contacts_and_space_lifecycle_workflow` 的 `cx:entity:` mention 为 `cx:flow:`；改写 `entity_types: ["message"]` → `object_kinds: ["message"]`；改写 `/index/entity?entity_id=` → `/index/object?object_id=`；改写 openapi snapshot test 的 `FacetName` / `ViewRenderer` / `allowed_entity_facets` 断言为 `allowed_object_facets`。 |
| T14 | `[x]` | `src/ids.rs` | `generate_notification_id` 从 `cx:notification:` 改为 spec-correct `cx:notif:` 前缀（spec id-kind-registry 用 `cx:notif:`）。 |

## 全 session 累计（rounds 1–6）

| 项目 | 累计变化 |
|---|---|
| Lib tests | **180 fail 3** → **184 / 184 全绿** |
| http_api tests | **12 / 42** → **39 / 39 全绿**（41 → 39 是 round 6 删了 2 个 entity/view 测试） |
| 新增端点（净） | 9 个 `/api/v1/index/*`、5 个 `/api/v1/repo/*`、1 个 `/api/v1/messages/send` |
| 删除端点 | 2 个 `/api/v1/entities` (round 6)、2 个 `/api/v1/views`（round 6）；`/api/v1/index/entity` 重命名为 `/api/v1/index/object` |
| 新增配置 | `SOLAND_ADMIN_PRINCIPAL_DIDS`、`SOLAND_ADMIN_PAGE_LIMIT`、`SOLAND_ADMIN_MAX_PAGE_LIMIT`、`SOLAND_PUSH_BRIDGE_CACHE_TTL_SECS`、`SOLAND_PUSH_BRIDGE_TRUSTED_SERVICE_DIDS` |
| 错误信封 | 双层嵌套 → flat `{ok: false, error: {errcode, error, request_id, …}}` |
| Spec validators | `ErrorCode` 36 → 46 variant；新增 `legacy_contract_removed`、`invalid_cursor`；production-mode 严格 JWS 验证 |
| Sync 协议 | `cx:cursor:` 完整字段集（profile / filter_hash / issued_at_ms / expires_at_ms / schema），无 `_*` 旧字段；legacy filter key 拦截；soft-delete + member-list 在 timeline 投影里诚实反映 |
| Push outbound | TTL freshness（默认 900s）、signed-service-DID 信任名单、auth_modes/privacy 来自远端契约、`todos[]` 全清 |
| Admin 写端点 | 5 个 `require_admin_principal` allowlist gate；admin_collection 死锁修；anchorer reconfig 升权双查；manual repair effects 强制 admin scope |
| Auth | `dev_login` auto-register；6 路 device_id 放宽；production-mode 严格 JWS |
| 投影路径 | `/messages/send` 同时落 projection_events；`cx.membership.join/leave` 派生投影；soft-delete space 过滤 |
| **概念清理 (round 6)** | **soland-local 的 `entity` / `entity_type` / `cx.entity.*` / `cx:entity:*` / `FacetName` / `ViewRenderer` / `allowed_entity_facets` 抽象全部 rip and replace**；`/index/entity` → `/index/object`；`entity_types[]` → `object_kinds[]`；mention type `entity` → `flow`；authz constraint `allowed_entity_facets` → `allowed_object_facets`。 |

## Spec 对齐审计（round 6 新建）

以下 typed-id 前缀在 soland 中出现但**不在** `contrix-spec/spec/v1/artifacts/registry/id-kind-registry.json`：

| 前缀 | 出现位置 | spec 对应 | 处置 |
|---|---|---|---|
| `cx:entity:*` | 已删 (T0–T13) | 无 | **已 rip-and-replace** ✓ |
| `cx:notification:*` | 已改 (T14) | `cx:notif:` | 改前缀 ✓（待 caller 实际接入） |
| `cx:org:*` | server-internal | 无 | 评估：org 是不是要走 `cx:space:` 父子关系而不是独立 id 类 |
| `cx:moderation:*` | server-internal | `cx:modq:` / `cx:report:` | 评估：迁移到 spec 类型 |
| `cx:keybackup:*` | server-internal | `cx:backup:` | 改前缀 |
| `cx:webrtc:*` | WebRTC session | `cx:call:` | 评估：WebRTC 走 call 流？ |
| `cx:thread:*` | 消息线索 | `cx:flow:` ? | 评估：thread vs flow 语义 |

以下 typed-id 前缀是合理的**server-internal** 派生类，spec 里没有但合理：

| 前缀 | 来源 |
|---|---|
| `cx:cursor:*` | sync token / index cursor（structured） |
| `cx:move:sha256:*` | Move id（content-addressed，spec 不枚举） |
| `cx:operation:*` | Move operation id |
| `cx:commit:*` | `/messages/send` 派生 commit id |
| `cx:device_pairing:*` | 配对挑战 token |
| `cx:invite-token:*` | invite-token 哈希字符串（与 `cx:invite:` 区分） |
| `cx:index:*` | index_query cursor token |
| `cx:push:*` | push device registration id |
| `cx:restore:*` | restore-ticket FSM id |

## 续作（按需续做）

### 跨仓 / 协调依赖

| 优先级 | 主题 | 续作 |
|---|---|---|
| M | `cx.membership.join` / `cx.membership.leave` | 当前在本仓作为 `operation_type="derived_projection"` 派生投影 surface；上游 `contrix-spec` 决策：要么加进 event-kind-registry，要么改 test 用 `cx.member.state`。 |
| M | `cx:notification:` → `cx:notif:` 前缀迁移 | `generate_notification_id` 已改成 spec-correct 前缀；测试 / 客户端如有读到旧 string 的话需要回归。 |
| M | 其他 spec-divergent typed-id 前缀清理 | 见上节"Spec 对齐审计"。`cx:moderation:` / `cx:keybackup:` / `cx:webrtc:` / `cx:thread:` 都是一句话能改的前缀重命名。 |
| M | `tests/move_anchor_wire.rs` 14 failed (pre-existing) | Move 构造 + Anchor pipeline 的真实签名验证缺口；独立立项。 |
| M | views / view registry 真实接入 | round 6 删除了 view scaffold；spec 的 `cx.view.create / .update / .reconcile` event 还没接 reducer，落到 reducer + 投影。 |
| L | snapshot chunk v2 | multi-chunk Merkle + signed generator proofs（spec v2）。 |
| L | `src/routing/system/describe.rs` 剩的 `todos[]` | self-describing manifest 内嵌示例迁出到 generated artifact（跨仓 `../_todos.md` C38.3）。 |
| L | `tests/http_api.rs` 41 处 legacy `dev_*` device_id | 系统性迁到 `cx:device:<uuidv7>` typed id。 |
| L | Repo commit submission | `cx.repo.submit_commit` 还是 scaffold；接进 reducer + commit-log Pg 表。 |
| L | admin compaction MAL-11 | 真正 compaction 要 fold + prune 历史 leaves。 |

### 内部债

| 优先级 | 区域 | 续作 |
|---|---|---|
| M | unused imports / dead_code warnings | 21+ 个 warning（来自历轮重构，未影响测试）。下一轮做 `cargo fix --lib`。 |
| L | sync cursor `v: "1"` 旧字符串字段 | 留下了 `v: "1"` + `version: 1` 双写；GA 前确认 SDK 只读 `version` 后再删。 |
| L | `cx:thread:` 在 messages_send | thread_id 作为 messages 分组主键；spec 用 `cx:flow:` 还是其他？需要 align。 |

## 维护规则

- 本文件只记 soland 仓内具体可执行的事项；任何跨仓协调（SDK / coauth / starid / cotest）都进 `../_todos.md`，本文件不重复。
- 完成一项就在表格里把 `[ ]` 标 `[x]`；过 1-2 轮后整理已完成项归并到一段 changelog，保持表格短。
- 不写兼容代码：v1 未发布，发现旧字段名 / 旧 schema 直接 rip and replace，validator + reducer + wire 三处一起改。
- 测试 fixture 中的 legacy plain-string device_id（41 处 `dev_alice` / `dev_bob` 等）暂不 mechanical 替换，由 dev_login / register / device_messages 等路径接受兜底。
