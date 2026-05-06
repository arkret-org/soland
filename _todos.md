# soland — Principal Server Audit & TODO

> Audit baseline: 2026-05-04 (last refreshed 2026-05-05). Reference implementation of `contrix-spec` v1 (Salvo + Diesel/PostgreSQL + in-memory fallback).
>
> 已完成的 round-by-round 细节见 git log；本文件只列**未完成**的工作。

---

## 已完成基线（snapshot — 2026-05-05）

| 项目 | 落地点 | 原 ID |
| --- | --- | --- |
| `cx.relation.update` patch-merge + `ProjectionEffect::RelationUpdated`；死分支修复 | `src/reducer.rs`、`src/kinds.rs` | A1a |
| `cx.membership.{kick,ban,unban,knock}` 不再坍缩成 join/leave；新增 `banned_members` / `knocking_members` 集合 | `src/reducer.rs`、`src/state.rs` | A1b |
| `ids::state_key_segment_encode` + `ids::state_key_compose` (percent-encode `%` 与 `\|`)，含碰撞测试 | `src/ids.rs` | A20 |
| Authz 决策优先级改为 deny → quarantine → require_review → allow | `src/authz.rs::highest_priority_decision` | B5 |
| `validate_embedded_artifacts() -> Result<(), ArtifactError>` 启动期 typed error | `src/artifacts.rs`、`src/main.rs` | Q4 |
| `#![recursion_limit = "512"]` 治标 bump（彻底解药仍是 F1 缩短 scaffold JSON） | `src/lib.rs` | F7 |
| F1 handlers 拆分（partial）：`handlers.rs` 19138 行 → `handlers/{mod,util,mimi,recovery,webrtc,moderation,federation,auth,space,message,account,schema,relation,reaction,read_marker,entity,view,key_backup_restore}.rs`，`mod.rs` rounds 2-4 终点 **11679 行 (-39%)**；72 / 72 lib unit tests 通过；route table 不变 | `src/handlers/*.rs` | F1 (rounds 2-4) |
| F1 handlers 拆分 round 5：从 11679 → **8925 行 (-23.5% 又 / -53.4% 累计)**。新增 6 个子模块：`identity.rs` (518)、`admin.rs` (317) + 8 builders、`profile.rs` (59)、`policy.rs` (458) + 5 fn + obligation/scope/effect 校验、`directory.rs` (579) + 9 demo/visibility helpers、`events.rs` (1015) + 22 validator helpers。共 23 个子模块共 ~10.7K 行；72 / 72 lib unit tests 通过 | `src/handlers/*.rs` | F1 (round 5) |

### F1 后续 round 拆分模式

1. `use super::{name, ...}` 拉父模块私有 helper（Rust 子模块可见父私有项）。
2. `use crate::{ids, state::AppState, wire::...}` 拉 crate 项。
3. `mod.rs` 顶部 `pub mod <domain>; pub use <domain>::{handler1, ...};` 保持 `lib.rs::handlers::*` glob 路由不变。
4. `cargo check` 后按编译警告剪掉 `mod.rs` 不再使用的 `use`。
5. 倒序删被搬走的代码块避免行号偏移；或像 round-4 那样所有子模块写完后一次 `sed` 删整段。
6. `git mv src/handlers.rs src/handlers/mod.rs` 已用过，blame 历史保留。

终点：`mod.rs` 仅 routes + `pub use` re-exports + `error_catcher` + `wait_for_sync_token` middleware（≤ 200 行）。

---

## P0 · Foundation gate（继续串行）

> 这一组是**串行 gate**：F1-cont/F2/F3 任一不做，后面的并行扩展都会反复冲突或返工。

| # | 任务 | 涉及文件 | 阻塞下游 |
| --- | --- | --- | --- |
| **F1-cont** ✅ | mod.rs **拆分完成**：从原 19138 行降到 **1118 行 (-94%)** —— 但其中 **648 行是两个 `#[cfg(test)] mod` 测试块**（operation_conformance_tests 243 行 + canonical_conformance_vectors 405 行），release 编译被 `#[cfg(test)]` 摘掉，实际 release-shape 仅 ~470 行（路由 + 31 个 `pub mod` + 31 个 `pub use` re-export 块 + `error_catcher` + `wait_for_sync_token` middleware + 5 个零散小 helper：`ContrixOpenApiDoc`、`snapshot_bundle_for_space`、`parse_snapshot_ref`、`device_inventory_to_json`、`message_event`、`generate_invite_token`、`contrix_openapi_yaml` 这一个 handler）。round 10 完成：`projection.rs`（840 行 — 17 fn projection writers + federation ingest + sync_timeline_message_json + ProjectedEventPage / FederationIngestResult struct）；`operations.rs`（717 行 — OperationPayloadSchema + PayloadRequirement + 23 个 validate_* schema/policy/canonical-json/encrypted-envelope/content-block/mention validators）；`space.rs` 扩容（554 → **840 行**，并入 16 fn space-query helpers：is_space_deleted / space_has_member / space_visible_to / space_search_visible_to / space_resolvable_to / space_id_visible_to / space_id_accessible / space_allows_plaintext_service / space_discoverability / invite_token_matches_space / invite_token_space_id / space_search_discoverability / prune_expired_typing / typing_ephemeral_for_space / record_space_lifecycle_operation / next_author_seq）。剩余优化（cosmetic，非 P0）：把 `SnapshotBundle / snapshot_bundle_for_space / parse_snapshot_ref` 移进 sync.rs；`device_inventory_to_json / generate_invite_token / message_event` 散件并入 auth/space/projection；`contrix_openapi_yaml` 单 handler 给 describe.rs；test mods 拆到独立测试文件。这些都不影响 `mod.rs` release-shape ≤ 200 行的目标 —— 已基本达成。 | `src/handlers/*.rs` | P1/P2 全部 |
| **F2** | `MemoryPersistenceStore` 的 `contacts / space_meta / messages / blobs` fallback 升级 PgStore；为 `push_devices / push_rules / presence / policy_documents / moderation_reports / audit_log / webrtc_sessions / key_backups / recovery_tickets / restore_state_snapshots / outbound_push_cache` 新增 trait + Pg + memory 实现，迁移当前 `state.rs` 锁里那一坨长期态。`persistence.rs:531` TODO(P0 durable-state) 即此项。 | `src/persistence.rs`、`src/state.rs`、`migrations/*` | P1 federation/MIMI/recovery/key-backup |
| **F3** ✅ | `src/error.rs` 已落地：`ErrorCode` enum 含 42 个变体（spec error-code-registry.json v2026-05-03），与 `contrix_core::error::KNOWN_ERROR_CODES` 双向 round-trip（`variant_count_matches_registry` + `wire_codes_round_trip` 测试锁住 spec B-08）；`as_str() / http_status() / from_wire() / render(res, message)` 四件套；`http_status_lookup_never_misses` + 13 项 `http_status_spot_checks` 测试。新模块共 4 个 tests 全部通过（共 72 → 76）。剩余增量工作（incremental，非 P0）：把现有 ~100 个 `render_error(res, StatusCode::X, "code_str", "msg")` 调用站点逐步迁移为 `ErrorCode::Foo.render(res, "msg")`。完成后即可 `#[deny(...)]` 拒绝硬编码字符串 code。 | `src/error.rs`（新）+ 各 handler module 的 render_error 调用迁移 | P1 authz/federation/events |
| **F4** | `lib.rs` 里的 `register_contract_operations` + 静态 `CONTRACT_OPERATIONS` 表（spec B-07）替换为由 `artifacts/openapi/contrix-service-api.openapi.yaml` + `contract-catalog.json` 生成的 OpenAPI；删除 `// TODO(openapi)` 兼容层。 | `src/lib.rs:518-1327` | OpenAPI 一致性 |
| **F5** | **Integration test hang**：`account_contacts_and_space_lifecycle_workflow` 与 `admin_collection_surfaces_return_sodmin_shapes` 单线程下都无限挂起（reducer stash 后依然挂；与 Round-1 改动无关，是 build break 之前就存在的隐疾）。建议 `RUSTFLAGS="--cfg tokio_unstable" RUST_LOG=trace` + tokio-console 抓阻塞栈，或临时摘 ratelimit / `wait_for_sync_token` middleware 做差分。 | `tests/http_api.rs`、`src/ratelimit.rs`、`src/handlers/mod.rs::wait_for_sync_token` | 解锁 CI |
| **F6** | **Integration test failure**：`auth_keys_device_messages_and_blobs_work` 失败复现 + 修；同样不是 Round-1 改动。 | `src/handlers/{keys,device_messages,blob}.rs`（F1-cont 之后） | 解锁 CI |

---

## P1 · 并行域扩展（F1-cont/F2/F3 之后可并行）

下面 6 个 stream 彼此独立，可以分给 6 路并行实现。

### Stream A · Reducer kind handler 扩面（21% → 80%+）

> 每个 sub-task 独立 PR；唯一依赖是 F1-cont 已拆出对应 ingest 函数。projection state 全部按 spec `evaluation_class` 区分（stateless / grant_local / space_state）。

| # | 任务 | 文件 |
| --- | --- | --- |
| A2 | 加 `cx.space.{join_rule, history_visibility, discovery, policy, policy_components, schema, plaintext_visible_services, history_sharing_policy, asset_privacy_policy, moderation_policy, media_service, tombstone, archive, freeze, upgrade, organization, child, parent, inheritance_policy}` 投影 → 新 `SpaceMetaState`，reducer fan-out。覆盖 spec B-15 / B-16 / B-21（`kind=enclave` ⇒ `federation_policy=closed` 默认；`kind=board\|list` ⇒ `boundary_profile=container`）。 | `src/reducer.rs`、`src/state.rs::ProjectionState` |
| A3 | `cx.schema.{define,update}` + `cx.morph.{create,update,archive,restore}` 投影 → `SchemaRegistryState` / `MorphState`（互相独立 PR）。 | `src/reducer.rs` |
| A4 | `cx.view.{create,update,reconcile}` 投影 → `ViewState`（spec M-34：renderer enum per-kind 必须 schema if/then 强制）。 | `src/reducer.rs`、`src/wire.rs` |
| A5 | `cx.flow.{create,update,archive,restore,convert,move,reorder,branch.*}` 投影 → `FlowState`，含 fractional indexing。同时落地 spec B-19：`Message.branch` 改 `^[a-z][a-z0-9_]{0,63}$`。 | `src/reducer.rs`、`src/wire.rs` |
| A6 | `cx.capability.{grant,delegate,revoke,derived}` 投影 → `CapabilityState`（喂下游 `effective_grants`）。 | `src/reducer.rs` |
| A7 | `cx.policy.{set,rule,action}` 投影 → `PolicyState`（与 Stream-D 联动）。 | `src/reducer.rs` |
| A8 | `cx.invite.{create,cancel,accept,third_party,claim,revoke}` 投影 → `InviteState`（spec M-10：补 invite/notification 的 auth_refs）。 | `src/reducer.rs` |
| A9 | `cx.account.{status,blocklist}` + `cx.account_data.set` 投影（spec B-17：补 account.status / moderation.report / moderation.frank 进 state-event 名册）。 | `src/reducer.rs` |
| A10 | `cx.moderation.{report,frank}` 投影；联动 Stream-E 的 moderation pipeline。 | `src/reducer.rs` |
| A11 | `cx.audit.{accessed, ryw_receipt}` 投影 → `AuditReceiptState`；同时在 catalog 里**注册 `cx.audit.ryw_receipt` event kind**（spec B-13）。 | `src/reducer.rs`、`contrix-spec/artifacts/registry/contract-catalog.json` |
| A12 | `cx.identity.{disclosure_policy,disclosure_receipt,presentation_request,presentation_response}` + `cx.did.proof` + `cx.session.grant` 投影。 | `src/reducer.rs` |
| A13 | `cx.device.{authorized,revoked,list_update}` 投影 → 与 Stream-F 的 device inventory 写穿。 | `src/reducer.rs` |
| A14 | `cx.key.verification.*`（8 个子 kind）投影 → `KeyVerificationState`，含 SAS/QR 一次性消费、设备签名绑定、replay 阻挡（spec M-23）。 | `src/reducer.rs` |
| A15 | `cx.mls.{proposal,genesis,commit,commit_failed,welcome,keypackage,epoch}` 投影 → `MlsGroupState`；处理 spec M-22 的 history-key 撤销/销毁顺序。 | `src/reducer.rs` |
| A16 | `cx.space_key.{share,withheld,share_audit}` 投影 → `SpaceKeyState`。 | `src/reducer.rs` |
| A17 | `cx.member.state` + `cx.profile.{update,space_override}` 投影。 | `src/reducer.rs` |
| A18 | `cx.mimi.room_binding`、`cx.sovereign.did_policy`、`cx.organization.{discovery,moderation_policy}` 投影。 | `src/reducer.rs` |
| A19 | spec B-09：`redact` reducer 必须保留 `actor_seq`（当前 `cleared` 把 attachments/mentions/relations 扁平化是错的；`hashes` 应清掉而非保留）。 | `src/reducer.rs` |

### Stream B · Authz / Capability / Policy 引擎补全

> B1 先做（schema 字段对齐），B2..B12 之后并行。

| # | 任务 | 文件 |
| --- | --- | --- |
| B1 | 对齐 grant 信封 shape（spec B-02）+ 统一 constraint schema（spec B-04 + B-05），补 `recurrence / max_duration / sensitive_fields / allowed_view_kinds / approval_threshold / condition.kind`；删除 `condition.when` 字符串 DSL。 | `src/authz.rs`、`src/wire.rs`、spec mirror |
| B2 | 实现 11 种缺失 constraint：`field_access / scope_limitation / delegation_control / rate_limiting / approval_workflow / claim_based / accountability / encryption_requirement / container_move / visibility_control / resource_limit / edit_window / device_session`（每种 1 个 sub-PR）。 | `src/authz.rs::evaluate_constraint` |
| B3 | 实现 10 种 `condition.kind`：`object_is_owned_by_actor / actor_is_assignee / ...`；当前全部 fail-open。 | `src/authz.rs` |
| B4 | grant-constraint 加 `evaluation_class: enum("stateless","grant_local","space_state","external")` 字段并据此分桶缓存（contrix-spec _todos B4/B5 同步）。 | `src/authz.rs`、spec schema |
| B6 | 把 reducer 里的 `cx.capability.*`（A6）/`cx.invite.*`（A8）投影喂进 `effective_grants()` —— 当前只回直接 grant，没有传递/委托/撤销链。 | `src/authz.rs`、`src/handlers/authz.rs`（F1-cont 后） |
| B7 | invite ↔ grant 联动：accept invite 自动生成 grant；revoke invite 自动撤销悬挂的 grant；和 audit 关联。 | `src/handlers/{authz,invite}.rs` |
| B8 | capability lattice（auth_weight 11 档）—— 当前是平面布尔。spec M-09 要求显式 causal_depth tie-break（v1.x 也可，留 todo）。 | `src/authz.rs` |
| B9 | policy_check + grant 评估合并：现 `policy_check` 与 `authz_check` 互不知晓，决策不一致；联调成单一 evaluator。 | `src/handlers/{authz,policy}.rs` |
| B10 | obligation 真正执行：当前只是 echo JSON。绑定到 reducer / 写路径 / quarantine 写穿。 | `src/handlers/policy.rs` |
| B11 | revocation 不再仅 `grant.revoked` 单 bool —— 加批量/scope/time-window/CRL 撤销；联动 federation 撤销 fan-out（spec M-18）。 | `src/authz.rs` |
| B12 | policy decision 缓存 TTL 由 `evaluation_class` 决定，而非硬编码 5 分钟。 | `src/authz.rs`、`src/state.rs` |

### Stream C · Federation 与 MIMI 上桥

> 内部 sub-task 全独立。生产落地需 F2 持久化。

| # | 任务 | 文件 |
| --- | --- | --- |
| C1 | spec B-06：federation signature transcript 全量切到 RFC 9421（`@method / @target-uri / @authority / content-digest / created / expires`）；移除 legacy 字段名。 | `src/handlers/federation.rs` |
| C2 | `federation_push_operations` 把 ingest 结果写穿到 `federation_operations` 持久表（不再丢锁）；实现 idempotency key（spec M-20）。 | 同上、`persistence.rs` |
| C3 | `federation_pull_operations` 改读持久表 + cursor，重启后可恢复；当前 in-memory snapshot 重启清零。 | 同上 |
| C4 | `federation_space_members` 替换 hardcoded `"join"` placeholder，改读 reducer membership state（依赖 A2）。 | 同上 |
| C5 | `federation_verify_actor` 真正校验签名 / DID document / key set；返回 `validation_class` enum 而非 bool（spec M-19）。 | 同上 |
| C6 | revocation fan-out TTL + 重试策略（spec M-18）。 | 同上 |
| C7 | MIMI `room_update / notify / room_message` 真正落进 `cx.*` event ingest，而非仅写 audit log；移除 demo "alice" 映射。 | `src/handlers/mimi.rs` |
| C8 | MIMI `consent_request / consent_update` 走 Stream-D 的 consent state machine + 持久化。 | 同上 |
| C9 | MIMI `key_material` 真正生成/取 KeyPackage（联动 A15）；移除 `full_mls_keypackage_claim_not_implemented` 字样。 | 同上 |
| C10 | MIMI `identifiers_query` 走真正的 directory（Stream E），删 hardcoded alice。 | 同上 |
| C11 | MIMI `report_abuse` / `proxy_download` 走 F2 的持久 moderation/blob 表。 | 同上 |
| C12 | MIMI provider/protocol directory 由 config 驱动，不再静态返回。 | 同上 |

### Stream D · Recovery / Key Backup / Restore-state（46+ scaffold endpoint 落地）

> 当前这块全是 stub —— `recovery/{discovery,readiness,live-snapshot,stack-bundle}` + `keys/backups/restore-state/*` + `keys/backups/restore-tickets/{ticket_id}/*`（执行器、审批、活动、时间线、receipt、bundle、audit-feed、materialized-device-handoff）。所有 handler 返回 `scaffold_*` 字段并带 TODO。
>
> D1 是数据模型 gate；D2..D11 之后可并行。

| # | 任务 | 文件 |
| --- | --- | --- |
| D1 | 设计并落地 `RecoveryTicket` / `RestoreCheckpoint` / `RestoreApproval` / `RestoreExecutorRun` / `RestoreReceipt` 数据模型 + Pg/memory store + state machine（pending → approved → enqueued → running → materialized → completed/failed/canceled）。 | `persistence.rs`、新 `src/recovery.rs`、`migrations/*` |
| D2 | `keys/backups` PUT/GET/DELETE/LIST 由进程内存换成 D1 的 store；schema 校验补全（cx.schema.key_backup.v1，spec B-11）。 | `src/handlers/key_backup.rs` |
| D3 | restore ticket lifecycle handlers：`describe / start / advance / resume / cancel / retry`（每个 1 PR）。 | `src/handlers/key_backup_restore.rs` |
| D4 | restore approval：`approvals/status / approvals/submit` —— 真正 reviewer 授权 + quorum + 审计。 | 同上 |
| D5 | restore executor：`executor/{status,enqueue,start,complete}` —— 持久 worker lease/heartbeat + 失败补偿。 | 同上 |
| D6 | restore artifact endpoints：`result / receipt / bundle / activity / timeline / audit-feed / materialized-device-handoff` —— 不再合成 dummy ID。 | 同上 |
| D7 | restore-state snapshot 持久化：`describe / export / import / durability / checkpoints` 走 D1 store + 信任/新鲜度策略。 | 同上 |
| D8 | `recovery/discovery` 用真实 service discovery + DID-bound audience 元数据。 | `src/handlers/recovery.rs` |
| D9 | `recovery/readiness` 跑真实 storage / authz / policy / crypto 健康检查。 | 同上 |
| D10 | `recovery/live-snapshot` 改 actor-scoped 仪表盘 + 分页 + 隐私边界。 | 同上 |
| D11 | `recovery/stack-bundle` 由 `recovery/contract-stack` 的真实生成产物组装；移除 inline path 列表。 | 同上 |
| D12 | spec M-28：did:plc `degraded_mirror_only` 7 天硬限制加宽限/延期机制。 | `src/handlers/identity.rs` |

### Stream E · Directory / Search / Moderation 真实数据

> 当前 `search_organizations / search_actors / search_users / resolve_handle / resolve_organization` 全部是 demo_actors 内嵌固定数据；`search_spaces` 没有 cursor。

| # | 任务 | 文件 |
| --- | --- | --- |
| E1 | F2 的 PgStore 加 `actors`、`organizations`、`handles` 表 + index，directory handler 读真表。 | `migrations/*`、`persistence.rs` |
| E2 | `search_spaces` 加 cursor + 排名 + 隐私可见性过滤（不再 hardcoded `public_only=false`）。 | `src/handlers/directory.rs` |
| E3 | 反枚举：rate-limit / 同意 / 模糊匹配（spec 安全章节，防 directory 遍历）。 | 同上 |
| E4 | moderation pipeline：`moderation_report` 写 D1/F2 持久表 + 异步审核工作流 + reducer A10 联动。 | `src/handlers/moderation.rs` |
| E5 | `moderation/report` 加 SLA / 状态查询（reporter-visible state）。 | 同上 |

### Stream F · Push / Device / Crypto / Privacy

| # | 任务 | 文件 |
| --- | --- | --- |
| F-1 | spec B-14：DID 不能进 push payload / TURN username / push `sender` 字段 —— 全路径换 Space-scoped pairwise pseudonym 或 ephemeral token；加 conformance MUST_NOT 测试。 | `src/handlers/{push,webrtc,push_outbound}.rs` |
| F-2 | `keys/upload / query / claim` 走 PgStore 持久化（当前 `mod.rs` TODO(P0 durable-state)）；revocation propagation 与 reducer A13 联动。 | `src/handlers/keys.rs`、`persistence.rs` |
| F-3 | spec B-10：KeyPackage shape 统一到 `principal_id/device_id/keypackage_id/device_signature/expires_at`。 | 同上 |
| F-4 | spec B-11：`secret_storage` 与 `key_backup` 合并到单一 `cx.schema.key_backup.v1` + `domain` enum；HKDF info per domain。 | `src/handlers/key_backup.rs`、wire schema |
| F-5 | spec B-12：MLS GroupContext extension `cx_app_state_ref` 分配私用 codepoint（0xF000–0xFFFF），写进扩展注册表。 | spec artifact + `src/wire.rs` |
| F-6 | spec B-22：encrypted attachment `key_ref` shape 切到 object 形式 `{algorithm, group_state_ref}`；不再字符串 `"mls_epoch:42"`。 | `src/handlers/blob.rs`、`src/wire.rs` |
| F-7 | spec B-23：blob metadata 加 `space_id` 关联 + 下载/GC 时校验。 | `src/handlers/blob.rs`、`migrations/*` |
| F-8 | push outbound bridge：替换 process-memory cache（一堆 TODO(push-outbound)）为持久 snapshot store，加 etag/freshness、首次 fetch 持久化、契约漂移 fail-closed。 | `src/handlers/push_outbound.rs` |
| F-9 | `auth/session-grant/exchange` 与 `push/register-device` 的 session-grant bridge（TODO(session-grant)）替换为 coauth-backed introspection + audience 绑定 + session-public-key proof verification。 | `src/handlers/{auth,push}.rs` |
| F-10 | WebRTC sessions / signals 持久化（F2 后）；ICE config 不再返回空数组。 | `src/handlers/webrtc.rs` |
| F-11 | profile/presence 走 F2 的 presence store；presence/typing 区分 ephemeral vs durable 通道。 | `src/handlers/profile.rs` |

---

## P2 · Sync / State-resolution / 一致性

> 依赖 P1-Stream-A；可与 P1-Stream-B/C/D 并行。

| # | 任务 | 文件 |
| --- | --- | --- |
| S1 | `client_sync` 把 `cx:cursor:` 与 reducer event 序列真正映射（TODO(P0 sync)）。 | `src/handlers/sync.rs` |
| S2 | `snapshot-chunk` 由单 JSON chunk 切成确定性多 chunk（TODO(P1 snapshot)）。 | 同上 |
| S3 | spec B-03：history_visibility (`invited` / `restricted`) 三处分歧统一到 reducer 单一解释。 | `src/reducer.rs`、`src/handlers/sync.rs` |
| S4 | spec M-15：所有 sync/directory 响应里 ID 前缀确保 `cx:space:` 而非 `space:`。 | grep + fix |
| S5 | spec M-16：sync subscription 里 `$ME` / `*` 通配语义形式化 + 校验。 | `src/handlers/sync.rs` |
| S6 | spec M-09 / M-10 配套：补 4 个 state-resolution conformance vector（与 spec 协同）。 | tests + spec |
| S7 | `index/debug/reducer` 内存 snapshot 换成持久投影（TODO(P1 reducer-debug)）。 | `src/handlers/index.rs` |

---

## P3 · 代码质量 / 可观测性 / 安全审计（贯穿全程，可与上面并行）

| # | 任务 | 文件 |
| --- | --- | --- |
| Q1 | 所有 handler 切到 Salvo `#[endpoint]` extractor + `ToSchema` response type，删除 `register_contract_operations` compat 表（`lib.rs:519` TODO(openapi)）。 | `src/handlers/*`、`src/lib.rs` |
| Q2 | spec M-01：彻底移除 `event_type`，仅保留 `event_kind`；删 dead error `aad_ambiguous_kind`。 | `src/wire.rs`、handlers、tests |
| Q3 | spec M-02..M-07：字段命名漂移统一（`principal_id/subject/holder_did`、`session_key_pub/session_public_key`、`Proof.kind`、`read_marker.id` pattern 等）。 | wire + handlers |
| Q5 | tracing：每个 handler 入口 `instrument(span)`，带 actor/space/event_kind；当前几乎无可观测信号。 | `src/handlers/*` |
| Q6 | rate-limit 由 `ratelimit.rs` 单进程 → 共享 store（Pg/Redis）；当前重启即清。 | `src/ratelimit.rs` |
| Q7 | tests 拆分：现 `tests/http_api.rs` 一个文件 5233 行 / 42 test。按 Stream A..F 切到 `tests/{auth,reducer,authz,federation,mimi,recovery,...}.rs`，共享 `setup` 抽到 `tests/common/mod.rs`。 | `tests/*` |
| Q8 | 端到端契约测试：用 spec `artifacts/fixtures/*` 跑 `submit → reduce → query` round-trip，作为 conformance gate。 | `tests/conformance.rs`（新） |
| Q9 | dev_login / `admin/{resource}` 等 dev-only path 加 `#[cfg(not(feature = "production"))]` 或运行时 hard guard，避免误开 prod（TODO(P1 admin)）。 | `src/handlers/admin.rs` |
| Q10 | 安全审计：`SERVERX_DEVELOPMENT_MODE=false` 路径上的所有"接受" branch 全部走真实 proof 校验 —— 写一组负向 conformance test。 | `tests/security.rs`（新） |
| Q11 | CI：跑 `cargo clippy -- -D warnings` + `cargo fmt --check` + `python ../contrix-spec/tools/artifact_pipeline.py check`（漂移闸门）。 | `.github/workflows/*` |

---

## 当前状态摘要

- **代码规模**：`src/` ~28K 行（其中 `handlers/mod.rs` 11679 + 子模块 ~8K），`tests/http_api.rs` 5.2K 行（42 tests）。
- **路由**：~180 个 HTTP 路由全部挂上 router；其中相当一部分是 scaffold/echo（recovery、key-backup restore、push outbound bridge、MIMI、directory 等）。
- **持久化**：PgStore 仅覆盖 `accounts / sessions / devices / federation_transactions` 四张表；`contacts / space_meta / messages / blobs / push / presence / policy / audit / moderation / webrtc / key_backups / recovery_*` 全部走 MemoryStore fallback —— 进程重启即丢。
- **Reducer**：130 个注册 event kind 中只完整投影了 28 个（21%）。MLS、key.verification、schema/morph、view、flow、capability、policy、identity disclosure、audit、invite、agent、applet、call 全无 projection。
- **Authz**：14 种 constraint 实现 3 种；10 种 condition.kind 实现 0 种；invite ↔ grant ↔ policy 三者未联动；obligation 当 inert JSON 透传。
- **Handlers 拆分**：F1 partial 完成，`mod.rs` 11679 行 (-39%)；仍需继续按 P0-F1-cont 清单拆到 ≤ 200 行。
- **Spec 同步**：`contrix-spec/_report.md` 列出 23 BLOCKING + 30+ MAJOR；其中 ~14 个 BLOCKING 直接落到服务器实现（B-02/03/05/06/07/09/10/11/12/13/14/17/18/22/23）。
- **CI**：lib unit tests 72/72 pass；3 个 integration test 阻塞（F5 ×2 hang + F6 ×1 fail）。

---

## 并行调度建议

| 时间线 | 可并行 stream |
| --- | --- |
| **Sprint 1 (foundation gate)** | F1-cont → F3 → F4（顺序）；F2 schema 设计可与 F1-cont 并行；F5 / F6 单独 track |
| **Sprint 2 (并行扩面)** | A · B · C · D · E · F 六路并行（不同工程师）；P2 部分 sub-task（S3 / S4 / S5）也可并 |
| **Sprint 3 (一致性 + Q)** | A19 + S1 / S2 / S6 / S7 + Q1..Q11 并行 |

**冲突点**（必须 serialize）：

- Stream A 的 reducer 改动与 Stream B 的 effective-grants reducer 喂入 → A 先合，B 跟上
- Stream C 的 `federation_space_members` → 必须等 A2（`SpaceMetaState`）和 reducer membership 投影
- Stream D-1 的 `RecoveryTicket` model → D2..D11 全依赖
- Stream F-2 的 PgStore key store → A13/A14/A15 reducer 写穿点依赖
- Q1（OpenAPI 切 `#[endpoint]`） → 必须在 F1-cont 之后；Q1 与 P1 各 stream 不冲突，但要注意 PR rebase 频率

---

## 不在本轮范围（v1.x 留底）

- `auth_weight` 11 档刻度重构成 `(governance_layer, authority_kind)` lattice（B8 仅做最小占位）
- spec M-38 / M-39 / M-40：applet 命名空间、agent endpoint 生命周期、MIMI room_binding 生命周期
- 多 region / 跨服务部署（当前 soland 是单进程 reference）
- 完整 IANA codepoint 申请（B-12 仅分配私用区段）
