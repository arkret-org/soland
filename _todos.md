# soland 项目本地 TODO

> 本文件聚焦 soland 仓本身的未完成 / 不符合 spec / 测试未通过的具体项。跨项目协调任务请看 `../_todos.md`。
> spec 参考：`contrix-spec/spec/v1/`、`contrix-spec/spec/v1/artifacts/`。
> 激进模式 — v1 未发布，发现 spec drift 直接 rip and replace，不留兼容垫片。

## 当前测试状态 (2026-05-15 round 7 close)

- `cargo test --lib` — **184 / 184** 全绿。
- `cargo test --test http_api` — **39 / 39** 全绿。
- `cargo test --test move_anchor_wire` — **28 / 28** 全绿。
- `cargo build` — **0 warning**。

## 续作（forward only）

以下条目都需要 contrix-rust-sdk 或运维侧动作，**不能在 soland 仓内独立完成**。

| 优先级 | 主题 | 依赖 / 处置 |
|---|---|---|
| M | MAL-11 真实 compaction | SDK 需要：(a) `Anchor.kind="compaction"` field；(b) `AnchorStore::prune_predecessor(anchor_id)`；(c) compaction policy spec。soland 端 `src/routing/admin/anchor.rs::admin_compact_anchor_dag` 已经在注释里枚举这三条 — 等 spec / sdk 落地后再接。 |
| M | per-admin signing key | KeyStore + session-grant introspection 提供 per-admin 签名密钥；当前 `admin_reconfigure_anchorer` 已经把 operator DID 接进 authz guard，签名密钥仍是 service-wide。 |
| M | Pg-backed `projection_events` | 现在 in-memory 为主，独立 migration 把 `state.persistence.projection_events()` 落到 Pg `projection_events` 表。trait 层已经准备好，只剩一份 SQL schema + `PgProjectionEventStore` impl。 |
| L | snapshot chunk v2 | SDK 需要：(a) `SnapshotChunker`（确定性分片）；(b) `SnapshotMerkleTree`；(c) `GeneratorProof`。soland 端 `src/routing/events/sync.rs::snapshot_chunk` 注释里枚举。 |
| L | OpenAPI 完整 `ToSchema` 化 | salvo-oapi 自动派生覆盖更多 wire 类型；本仓有 ~50 个 `ToSchema` 注解，spec 期望 ~100。机械工作，没新概念。 |

## 维护规则

- 本文件只记 soland 仓内具体可执行的事项；任何跨仓协调（SDK / coauth / starid / cotest）都进 `../_todos.md`，本文件不重复。
- 完成一项就在表格里把 `[ ]` 标 `[x]`；过 1-2 轮后整理已完成项归并到 git log，保持表格短。
- 不写兼容代码：v1 未发布，发现旧字段名 / 旧 schema 直接 rip and replace，validator + reducer + wire 三处一起改。
- spec-divergent typed-id 前缀和 event kinds 优先在本仓处理（rename 是单方面动作）；只在影响 spec 注册表本身时进 `../_todos.md`。
- 历史变更（哪轮删了哪个概念、哪轮哪个 prefix 改了名）查 `git log` — **不要**在本文件里维护"deleted things"列表，避免下一轮 agent 误以为还要做。
