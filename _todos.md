# soland 项目本地 TODO

> 本文件聚焦 soland 仓本身的未完成 / 不符合 spec / 测试未通过的具体项。跨项目协调任务请看 `../_todos.md`。
> spec 参考：`contrix-spec/spec/v1/`、`contrix-spec/spec/v1/artifacts/`。
> 激进模式 — v1 未发布，发现 spec drift 直接 rip and replace，不留兼容垫片。

## 当前测试状态 (2026-05-16)

- `cargo test --lib` — **202 / 202** 全绿
- `cargo test --test http_api` — **51 / 51** 全绿
- `cargo test --test move_anchor_wire` — **28 / 28** 全绿
- `cargo test --test openapi_typed` — **1 / 1** 全绿
- `cargo build` — **0 warning**
- 总 **282 tests pass**

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

## 续作(round 15+ 候选)

| 优先级 | 主题 | 处置 |
|---|---|---|
| M | ~~Applet / Agent 集成测试 + 服务端 admin snapshot 实际数据填充~~ | ✅ 2026-05-16 已落地(round 15b)。 |
| M | Pg-backed `projection_places` / `projection_flows` / `projection_morphs` | 三张表 schema 都就绪,差 `PgPlaceProjectionStore` / `PgFlowProjectionStore` / `PgMorphProjectionStore` impl + reducer write-through + startup hydrate。 |
| M | Pg-backed `projection_events` | 独立 migration:`projection_events` trait 已经准备好,只缺一份 SQL schema + `PgProjectionEventStore` impl。 |
| M | MAL-11 prune walk 自动化 | 当前 `anchor-dag/prune` 只支持显式 `{anchor_id}` 调用;后台 worker 周期性遍历 DAG 跑 `CompactionPolicy::is_eligible` 也可以做,但要先有运营痛点。 |
| L | OpenAPI ToSchema 下一批 untyped handler | round 14c 把 round-12 forward-compat 套件(4+1 个 schema)做完;剩 ~25 处 `req.parse_json::<T>()` + `&mut Response` handler 等同款转换(grep `req.parse_json::<` + `&mut Response` 找候选)。 |
| L | Registry 化非 canonical errcode | `src/routing/identity/did.rs` 之外的文件里残留的非 registry 码值得后续单独清理(grep `render_error` 找候选)。 |
| L | Tombstoned / terminal Place 是否对外可见 | 当前 `GET /projection/places` 返回所有 state;tombstone 是「删除」语义,客户端不应看到。下个 round 加 `?include_state=` 查询参数(默认排除 tombstoned;explicit 请求才返回)。 |
| L | OpenAPI typed signature for projection_query handlers | round 14d / 15a 的三个 handler 还是 `&mut Response + res.render(Json(json!{...}))` 形态。 |
| L | Snapshot v2 multi-chunk fixture | 当前 B4 跑的是 single-chunk case;构造一个大于 256 KiB 的测试 space 来真的走 audit_path 非空路径。 |

## 维护规则

- 本文件只记 soland 仓内具体可执行的事项；任何跨仓协调（SDK / coauth / starid / cotest）都进 `../_todos.md`，本文件不重复。
- 完成一项就在表格里把 `[ ]` 标 `[x]`；过 1-2 轮后整理已完成项归并到 git log,保持表格短。
- 不写兼容代码:v1 未发布,发现旧字段名 / 旧 schema 直接 rip and replace,validator + reducer + wire 三处一起改。
- spec-divergent typed-id 前缀和 event kinds 优先在本仓处理(rename 是单方面动作);只在影响 spec 注册表本身时进 `../_todos.md`。
- 历史变更(哪轮删了哪个概念、哪轮哪个 prefix 改了名)查 `git log` — **不要**在本文件里维护"deleted things"列表,避免下一轮 agent 误以为还要做。
