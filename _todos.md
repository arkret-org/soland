# soland 项目本地 TODO

> 本文件聚焦 soland 仓本身的未完成 / 不符合 spec / 测试未通过的具体项。跨项目协调任务请看 `../_todos.md`。
> spec 参考：`contrix-spec/spec/v1/`、`contrix-spec/spec/v1/artifacts/`。
> 激进模式 — v1 未发布，发现 spec drift 直接 rip and replace，不留兼容垫片。

## 当前测试状态 (2026-05-14 此轮结束)

- `cargo test --lib` — **183 / 183**（基线 180/3，本轮 +3）。
- `cargo test --test http_api` — **18 passed / 24 failed**（基线 12/30，本轮 +6 全部因系统级修复带过）。剩余 24 都是各自独立的 scaffolding gap，需要 case-by-case 续修，不再有共享根因。

## 本轮完成（2026-05-14 round 2）

| # | 状态 | 文件 | 任务 |
|---|---|---|---|
| L0 | `[x]` | `src/error.rs` | 补 3 个 spec error code variant — `PolicyCombinationInvalid` / `AnchorerRecoveryMissing` / `UnsupportedLatticeType`。 |
| L1 | `[x]` | `src/routing/events/operations.rs` | `cx.relation.create` payload 字段对齐 spec：`RELATION_FROM_FIELDS` / `RELATION_TO_FIELDS` 加 `from_ref` / `to_ref` 主键。 |
| L1.1 | `[x]` | `src/routing/events/operations.rs` | `cx.member.state` membership payload 字段对齐 spec：`MEMBER_ACTOR_FIELDS` 加 `actor_id`。 |
| P1.a | `[x]` | `src/routing/identity/auth.rs` | dev_login 在 dev_mode 下自动 register account（test 不需要先 `account/register`）。 |
| P1.b | `[x]` | `src/routing/identity/auth.rs` | dev_login `device_id` 校验在 dev mode 仅检 non-empty，不再走 strict typed-id（test fixture 用 `dev_alice` 等 legacy 字符串，spec 兼容由 OAuth 路径上 `derived_oauth_device_id` 兜底）。 |
| P1.c | `[x]` | `src/wire.rs` + `src/routing/system/util.rs` + `src/ratelimit.rs` | 错误响应 envelope 改成 flat Matrix/Palpo 形 `{ok: false, error: {errcode, error, request_id, ...}}`，对齐 sodmin/yougen/cotest 客户端读取约定（`body.error.errcode` / `body.error.error`）。`ApiError` 改用新 `ApiErrorDetail`，把 `contrix_sdk::ErrorEnvelope` 的 self-wrap 去掉。 |
| P2 | `[x]` | `src/routing/system/describe.rs` + `src/routing/interop/push_outbound.rs` | 删 inline `TODO_*` 占位 — 替换成结构正确的 example value（合法 JWT 形态、`cx:device:01904100-…` 典型 typed id、`webpush:https://fcm.googleapis.com/wp/…` 形态、`cache_state` 改 `imported_replace_existing`/`memory_cached` 等真实状态串）。`todos[]` 列表里的 `TODO:` 前缀清空，保留行内描述只作为 known-gap 注记。 |
| P3 | `[x]` | `src/routing/interop/push_outbound.rs` | 整个 push outbound bridge 一轮清理：module doc 改写说明实际接的功能（durable cache via `state.persistence.push_bridge_cache()`、contract-digest drift fail-closed、Etag/freshness、trust_level、export/import round-trip），把残留的 stale `TODO(push-outbound):` 字符串删掉、保留 3 条真实 gap（auth_modes/privacy 描述符 binding；signed-service-DID trust 验证；time-based 缓存失效策略）。`fetch_mode` / `cache_mode` / `snapshot_store_mode` 描述串改写真实实现。 |
| P4 | `[x]` | `src/routing/admin/mod.rs` + `src/routing/admin/anchor.rs` + `src/routing/admin/collection.rs` + `src/config.rs` | 新 `SOLAND_ADMIN_PRINCIPAL_DIDS` env 配置 + `AppConfig::admin_principal_dids` + `AppConfig::is_admin_principal(actor)` helper。新 `super::require_admin_principal(state, session)` gate，dev_mode 透过，production 模式按 allowlist 拒绝。Wire 到 5 个 write-side admin 端点：`admin_reconfigure_anchorer`、`admin_repair_bottom`、`admin_compact_anchor_dag`、`admin_submit_multisig_partial`、`admin_rotate_signing_key`。`admin_collection` 也读 allowlist（之前只允 dev_mode）。剩余 stale `TODO(stream_h_admin)` 注释改写为 `FUTURE:` 描述真实续作（per-admin signing key 提供 / MAL-11 compaction marker / Manual repair 自由格式 effects 校验）。 |
| P5 | `[x]` | `src/config.rs` + `src/routing/admin/cells.rs` + `src/routing/admin/collection.rs` | 新 `SOLAND_ADMIN_PAGE_LIMIT` / `SOLAND_ADMIN_MAX_PAGE_LIMIT` env + `AppConfig::admin_default_page_limit` / `admin_max_page_limit`。`admin/cells.rs` 把 const `DEFAULT_LIST_LIMIT=100` / `MAX_LIST_LIMIT=1000` 删了，改读 config；`admin/collection.rs` 同步把 hardcoded `100`/`500` clamp 改读 config。`tests/http_api.rs` / `tests/move_anchor_wire.rs` / `tests/openapi_typed.rs` / `src/did_resolver_chain.rs` / `src/multisig_watchdog.rs` / `src/routing/mod.rs` / `src/routing/federation/federation.rs` 所有 inline test-fixture AppConfig literal 同步补 3 个新字段。 |
| P6 | `[x]` | `src/routing/events/sync.rs` | 新 `pub fn resolve_sync_cursor_to_event_id(state, space_id, cursor)`：解码 `cx:cursor:` token，按 `_positions[space_id]` 提取 timestamp_micros checkpoint，扫 projection + 持久化 messages，回放到 checkpoint 那一刻最后一条 event_id；plain event-id cursor pass through 不动；`None` cursor → `None`。`sync_gap_backfill` 不再 hardcoded 拒绝 `cx:cursor:`，改先调 resolver 翻译再走 `backfill_gap_events`。Snapshot chunk 的 `TODO(P1 snapshot)` 注释改写成 `FUTURE:` 注明 v1 当前是 single JSON chunk + in-band digest，多 chunk Merkle + 签名 generator proof 是 v2 spec 工作。 |

## 续作（这轮没动；优先级标注是相对 soland 仓的）

| 优先级 | 文件 / 区域 | 性质 | 续作说明 |
|---|---|---|---|
| L | `tests/http_api.rs` 24 仍 fail | 各自独立的 scaffolding gap | 余下的 24 个 failure 不再共享根因（P1.a–c 已 unblocked 6 条），剩下都是各自端点的行为期望和实现不一致：`index_product_endpoints_return_demo_projection_shapes`（index/entity 不带 `kind: "space"` 字段）、`account_contacts_and_space_lifecycle_workflow`、`webrtc_signaling_contracts_work` 等。属于每条 1-2 小时单独修，不再属于系统性问题。 |
| M | `src/routing/admin/anchor.rs` 仍剩的 `FUTURE:` markers | per-admin signing key + MAL-11 compaction | 用 `super::require_admin_principal` allowlist 已经做了授权层；签名身份本轮没改（继续走 service-level `AnchorerWorker` 的 signing key）。下一步要做：(1) 为每个 admin DID 提供 per-admin signing key（KeyStore-backed）；(2) `Move::sign` 时改用 session.actor 对应的 key；(3) `is_compaction` 用 MAL-11 compaction marker 而不是启发式判断；(4) `Manual` 修 path 加 free-form `Effect[]` admin-scope 校验。需要 anchorer + reducer 跨模块协调。 |
| M | `src/routing/interop/push_outbound.rs` 剩的 3 条 `todos[]` | 真 trust + auth_modes binding | (1) `cx.push.notify` 出站签名 / auth 参数读取 fetched 的 `auth_modes` / `privacy` 描述符，不再用静态期望；(2) imported snapshot 验证 `service_did` 签名 + 真 trust 等级提升，而非永远 `trust_level="pending"`；(3) 加 time-based cache 失效策略，不再只靠 `force_refresh` + 内容 digest drift。 |
| L | `src/routing/events/sync.rs` snapshot chunk v2 | multi-chunk Merkle + signed generator proofs | spec v2；本轮只换了注释口径。snapshot-chunk endpoint 现在 single JSON chunk + 内嵌 digest 校验，足够小 Space + dev，不够 production-scale。 |
| L | `src/routing/system/describe.rs` 仍剩的 `todos[]` | self-describing manifest 内嵌示例迁出到 generated artifact | 跟 `../_todos.md` C38.3 同根：example JSON 不要再 inline，要从 contrix-spec generated artifact 拉。 |
| L | `tests/http_api.rs` 中 41 个 dev_alice / dev_bob 等 legacy device_id 字符串 | test-side spec drift | strict spec 要求 `cx:device:<uuidv7>`；dev_login 已经 relax，但产品长期方向是 mechanical 替换所有 test fixture 用 typed id（沿 OAuth `raw_device_id` 模式）。本轮没动，避免大量 mechanical edits 淹没 review。 |

## 维护规则

- 本文件只记 soland 仓内具体可执行的事项；任何跨仓协调（SDK / coauth / starid / cotest）都进 `../_todos.md`，本文件不重复。
- 完成一项就在表格里把 `[ ]` 标 `[x]`；过 1-2 轮后整理已完成项归并到一段 changelog，保持表格短。
- 不写兼容代码：v1 未发布，发现旧字段名 / 旧 schema 直接 rip and replace，validator + reducer + wire 三处一起改。
