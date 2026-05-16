# soland 项目本地 TODO

> 本文件聚焦 soland 仓本身的未完成 / 不符合 spec / 测试未通过的具体项。跨项目协调任务请看 `../_todos.md`。
> spec 参考：`contrix-spec/spec/v1/`、`contrix-spec/spec/v1/artifacts/`。
> 激进模式 — v1 未发布，发现 spec drift 直接 rip and replace，不留兼容垫片。

## 当前测试状态 (2026-05-16)

- `cargo test --lib` — **209 / 209** 全绿
- `cargo test --test http_api` — **57 / 57** 全绿
- `cargo test --test move_anchor_wire` — **28 / 28** 全绿
- `cargo test --test openapi_typed` — **1 / 1** 全绿
- `cargo build` — **0 warning**(单条 `agent_bridge::REFERENCE_AGENT_AUDIT_HMAC_KEY` dead_code 是 user 在做的 Sprint Q1 19,跨我们的范围)
- 总 **295 tests pass**

## 已完成历史(详情查 git log + `CHANGELOG.md`,本文件不重复)

- **round 10**(2026-05-15)— Place lifecycle 收敛:`cx.place.{archive,restore,tombstone}` canonical-kind 注册表 + wire validator
- **round 11**(2026-05-15)— Place projection state machine + 412 admission preflight
- **round 12**(2026-05-15)— OpenAPI 第一遍 ToSchema 派生(4 个 federation/webvh wire 类型,handler 仍 untyped)
- **round 13**(2026-05-16)— Flow / Morph projection state machine(SQL migration、reducer、state guard、412 wire);SDK round 10 配套(archive/tombstone/update 源状态守卫)
- **round 14a**(2026-05-16)— Flow position events(`cx.flow.{move,reorder}`)接入 + reducer touch
- **round 14b**(2026-05-16)— `cx.redaction` 对 Flow / Morph 终态推进 + 412 preflight + SDK round 11 对称实现
- **round 14c**(2026-05-16)— OpenAPI ToSchema 收尾:federation_anchors_pull/push + embedded_webvh_register 三 handler 转 typed signature;forward-compat guard 翻成 positive assertion
- **round 14d**(2026-05-16)— Place / Flow projection read-side endpoints(`GET /api/v1/projection/{places,flows}`)
- **round 14e**(2026-05-16)— `cx.flow.track.*` wire validator + state guard;SDK round 12 配套(`OP_FLOW_TRACK_*` + 4 reducer helpers)
- **round 14f**(2026-05-16)— Applet / Agent protocol family wire validators(5 applet + 4 agent sub-events)+ admin snapshot 端口注册;SDK round 13 配套(9 个 `OP_*` 别名 + operation registry 条目,**不**进 BUILT_IN_OPERATION_KINDS)
- **round 15a**(2026-05-16)— Morph projection 读端(`GET /api/v1/projection/morphs?space_id=...`),完成 round 14d 的 Place/Flow/Morph 三人组
- **round 15b**(2026-05-16)— Applet / Agent 服务端 admin snapshot 实际数据填充。`ProjectionState::{applets,agents}` 双新 map + `AppletProjection` / `AgentProjection` struct + reducer 处理 `cx.applet.{registration,discovery}` / `cx.agent.endpoint`(session-scoped 事件依然不进 projection,见 round 14f);`admin_applet_items` / `admin_agent_items` 从 in-memory projection 读,取代之前的 `Vec::new()` stub。Bonus:修了 user 上游 SDK `key_verification.rs::EphemeralX25519Keypair` 缺 `Clone` derive 的 build break。
- **round 15c**(2026-05-16)— OpenAPI typed signature for projection_query handlers(`places` / `flows` / `morphs` 三个 handler 全部转 `JsonResult<T>` + 6 个 ToSchema response/row struct + `QueryParam<String, true>` + `AuthArgs`)。`openapi_typed.rs` 加 6 条 positive assertion。继续 round 12 / 14c 的 OpenAPI 完整度工作。
- **round 15d**(2026-05-16)— Terminal-state visibility filter for projection_query handlers。三个 handler 加 `include_terminal: QueryParam<bool, false>` 可选参数;默认 `false` → 隐藏 tombstoned(Place)/ deleted+redacted(Flow/Morph)。spec rationale:终态 unrecoverable,客户端 hydrate kanban 视图不应看到。 explicit `?include_terminal=true` 返完整集供 audit / undelete UI。
- **round 15e**(2026-05-16)— Non-canonical errcode 清理。把 18 处 `"persistence_error"` + 5 处 `"blob_store_error"` + 1 处 `"serialization_error"` + 2 处 `"projection_error"` + 1 处 `"backfill_error"` 都映射成 `"internal_error"`;`"event_too_large" → "payload_too_large"`、`"actor_seq_conflict" → "cas_conflict"`、`"missing_dependency"/"missing_auth_ref" → "dependency_missing"`、`"limit_exceeded" → "quota_exceeded"`、`"unauthorized" → "unauthenticated"`、`"snapshot_stale" → "stale_frontier"`、`"hash_mismatch" → "digest_mismatch"`、`"policy_denied" → "capability_denied"`、`"invalid_semantics" → "schema_violation"`。HTTP status code 保留,只换 errcode 字符串;federation peer rejection JSON literal(`json!({"reason": "persistence_error"})`)与 SDK enum-to-string 转换表(`admin/anchor.rs`)不动 —— 它们不是 HTTP errcode。
- **round 15f**(2026-05-16)— Snapshot v2 multi-chunk fixture(round B4 留下的覆盖盲点)。新测试 `snapshot_v2_multi_chunk_fixture_verifies_non_empty_audit_path`:塞 80 条 ~4 KB body 的 message 让快照 total_bytes >256 KiB,验 `chunk_count ≥ 2` + 每个 chunk 的 `audit_path` 非空 + `SnapshotMerkleTree::verify` 重建到 `merkle_root`。补的是单 chunk 测试不走的 sibling chain 路径。
- **round 15g**(2026-05-16)— OpenAPI typed signature for `access/authz.rs::invites` + `effective_grants`(下一批 untyped handler 转 typed 的第一步,延续 round 12 / 14c / 15c 的工作)。两 handler 都改 `JsonResult<T>` 签名(`InvitesResponse` / `EffectiveGrantsResponse` 早就有 ToSchema),`invites` 用 `AuthArgs`;operation_id 保留 spec 既定的 `cx.authz.get_invites` / `cx.authz.get_effective_grants`(与 SOLAND_EXTENSION_OPERATIONS 表对齐)。`openapi_typed.rs` 加 2 个 schema + 2 个 operationId 断言。后续 batch 还有 ~94 个 untyped handler 候选(grep `req: &mut Request.*res: &mut Response` 找)。
- **round 15h**(2026-05-16)— Pg-backed `projection_places` / `projection_flows` / `projection_morphs` 全套持久化(round 15+ 候选里最大的一项)。`persistence.rs` 加 3 个 store trait + 3 个 `PlaceProjectionRecord` / `FlowProjectionRecord` / `MorphProjectionRecord` 类型 + 3 个 Memory impl + 3 个 Pg impl(diesel `sql_query` + upsert,sql 与 migrations 20260515/20260516 schema 一一对齐)+ `PersistenceStore` trait 加 `place_projections()` / `flow_projections()` / `morph_projections()` accessor。`routing/events/projection.rs::write_through_projection` 在 reducer apply 后(锁释放外)snapshot 投影并 upsert 到持久化,覆盖 Place/Flow/Morph 的全部 lifecycle / position / track 事件 + `cx.redaction` 的 `object_ref` 路径。`state.rs::hydrate_projections_from_persistence` 在 `AppState::new` 时把三张表回读入 in-memory `ProjectionState`,所以进程重启不丢 lifecycle 状态。新 integration test `projection_persistence_write_through_mirrors_lifecycle_events` 走真 wire 验 Place create+archive、Flow create+redact、Morph create+archive 都写穿透到 persistence。Pg backend 没专门跑通测试(测试用 MemoryPersistenceStore),但 SQL shape 走 `sql_query` 对齐既有 schema —— 部署到 Pg 时验。
- **round 15i**(2026-05-16)— Pg-backed `projection_events`(append-only mirror of in-memory `ProjectionEventRecord` stream)。新 migration `migrations/20260516010000_projection_events/{up,down}.sql`:`projection_events` 表(BIGSERIAL `ordinal` 主键 + event_id/space_id/event_kind/operation_type/operation_id/sender/payload/created_at);两个索引(space_id / created_at)。`schema.rs` 加 diesel `table!` 块。`PgProjectionEventStore`(`sql_query` INSERT + SELECT ORDER BY ordinal)接入 `PgPersistenceStore`,删掉先前的 `fallback.projection_events()` 委托。Memory mode 测试链路无 regression(295 tests pass)。Pg backend 没专门 CI(需要 Postgres);schema + diesel shape 与既有 PgPolicyDocumentStore / PgPlaceProjectionStore 同款,部署时验。

## 续作(round 15+ 候选)

| 优先级 | 主题 | 处置 |
|---|---|---|
| M | ~~Applet / Agent 集成测试 + 服务端 admin snapshot 实际数据填充~~ | ✅ 2026-05-16 已落地(round 15b)。 |
| M | ~~Pg-backed `projection_places` / `projection_flows` / `projection_morphs`~~ | ✅ 2026-05-16 已落地(round 15h)。 |
| M | ~~Pg-backed `projection_events`~~ | ✅ 2026-05-16 已落地(round 15i)。 |
| M | MAL-11 prune walk 自动化 | 当前 `anchor-dag/prune` 只支持显式 `{anchor_id}` 调用;后台 worker 周期性遍历 DAG 跑 `CompactionPolicy::is_eligible` 也可以做,但要先有运营痛点。 |
| L | OpenAPI ToSchema 下一批 untyped handler(剩余) | round 15g 转了 access/authz 的 invites + effective_grants 两个。grep `req: &mut Request[^)]*res: &mut Response` 还能找到 ~94 个 GET/POST handler 候选;每个独立 PR 工作量小但累加大。优先级 L。 |
| L | ~~Registry 化非 canonical errcode~~ | ✅ 2026-05-16 已落地(round 15e)。 |
| L | ~~Tombstoned / terminal Place 是否对外可见~~ | ✅ 2026-05-16 已落地(round 15d)。三个 projection endpoint 都加了 `include_terminal=true|false` query param;默认 hide。 |
| L | ~~OpenAPI typed signature for projection_query handlers~~ | ✅ 2026-05-16 已落地(round 15c)。 |
| L | ~~Snapshot v2 multi-chunk fixture~~ | ✅ 2026-05-16 已落地(round 15f)。 |

## 维护规则

- 本文件只记 soland 仓内具体可执行的事项；任何跨仓协调（SDK / coauth / starid / cotest）都进 `../_todos.md`，本文件不重复。
- 完成一项就在表格里把 `[ ]` 标 `[x]`；过 1-2 轮后整理已完成项归并到 git log,保持表格短。
- 不写兼容代码:v1 未发布,发现旧字段名 / 旧 schema 直接 rip and replace,validator + reducer + wire 三处一起改。
- spec-divergent typed-id 前缀和 event kinds 优先在本仓处理(rename 是单方面动作);只在影响 spec 注册表本身时进 `../_todos.md`。
- 历史变更(哪轮删了哪个概念、哪轮哪个 prefix 改了名)查 `git log` — **不要**在本文件里维护"deleted things"列表,避免下一轮 agent 误以为还要做。
