# soland Active TODO

> 更新日期: 2026-04-29
> 范围: soland 现在只跟踪 Principal Server / Repo / Sync / Index / Blob / Federation 的服务端落地任务。

## 0. 当前边界

- [x] Identity Registry 服务端任务已迁移到 `E:\Works\contrix-dev\starid\_todos.md`。
- [x] `cx.profile.identity_registry.v1` 不再作为 soland active TODO 跟踪；soland 只保留当前 `identity/*` 兼容入口用于本地联调。
- [x] 已完成的 canonical operation、canonical JSON/hash、commit proof binding、service DID 配置、CORS 配置和 sync token binding 不再重复列为待办。
- [x] 长期扩展 profile 从 active TODO 移除；这些不是当前 soland 服务端收敛路径的直接阻塞项。

当前可验证基线:

- `cargo test` 已通过: 63 个单元测试 + 25 个 HTTP 合同测试。
- HTTP API 覆盖 account、repo、sync、directory、index、authz、keys、device messages、blob、push、federation、WebRTC、moderation 等入口。
- PostgreSQL repo adapter 已存在；大量业务状态仍在内存 `AppState` 中。
- 仍未满足完整 Contrix v1 profile 的主要原因: 持久化、跨实例一致性、authz causal frontier、sync/federation/snapshot 完整语义。

## 1. Profile 收敛目标

| Profile | 当前状态 | 下一步阻塞项 |
| --- | --- | --- |
| `cx.profile.principal_server_repo_api.v1` | PARTIAL | PostgreSQL store、事务写路径、真实 schema conformance、authz at frontier |
| `cx.profile.principal_server.v1` | PARTIAL | 持久 sync positions、account/session/device/blob/push 状态持久化、跨实例 fanout |
| `cx.profile.index_node.v1` | PARTIAL | 持久 projection、query schema、auth filtering、stale frontier |
| `cx.profile.blob_node.v1` | PARTIAL | blob metadata PG、访问授权、quota、retention |
| `cx.profile.federation_node.v1` | PARTIAL | HTTP Message Signatures、replay 持久化、fork quarantine |

## 2. P0: Durable Server

目标: 重启后不丢业务状态, 多实例写入不会破坏 repo/projection/audit 一致性。

### 2.1 Store 抽象与迁移约束

- [ ] 定义 `PersistenceStore` 边界:
  - [ ] 明确哪些状态继续归 `RepoAdapter`, 哪些状态进入 `PersistenceStore`。
  - [ ] 为 account/session/contact/space/message/device/blob/push/policy/audit/federation/sync positions 定义 trait 方法。
  - [ ] Memory store 与 PostgreSQL store 共用同一组行为测试。
  - [ ] handler 不直接读写新增业务状态的 `Arc<Mutex<...>>`。
- [ ] PostgreSQL migration 分层:
  - [ ] 每类业务表有 primary key、updated_at、created_at。
  - [ ] 所有幂等写入有唯一约束。
  - [ ] 所有 cursor / pagination 查询有稳定索引。
  - [ ] migration down.sql 可回滚本次新增表。
- [ ] 数据库错误映射:
  - [ ] unique violation -> idempotency conflict 或 duplicate accepted。
  - [ ] serialization/deadlock -> retryable 503。
  - [ ] not found / not visible 维持同一 error envelope。

### 2.2 Account / Session

- [ ] `account/register` 持久化:
  - [ ] DID 唯一。
  - [ ] handle 唯一且规范化。
  - [ ] duplicate same payload 幂等返回。
  - [ ] duplicate different payload 返回 conflict。
- [ ] `account/me` 从 store 读取, 不依赖内存 demo account。
- [ ] account lifecycle:
  - [ ] disabled account 拒绝登录和写入。
  - [ ] locked account 允许只读查询。
  - [ ] erased account 的目录/搜索不泄露 profile。
- [ ] session 持久化:
  - [ ] token hash 存储, 不落明文 token。
  - [ ] actor + device_id + expires_at 绑定。
  - [ ] logout 写 revoked_at。
  - [ ] expired/revoked session 返回统一 unauthenticated envelope。

### 2.3 Space / Contact / Membership

- [ ] contacts 持久化:
  - [ ] request 幂等。
  - [ ] accept/reject CAS。
  - [ ] accepted contact 参与 actor visibility 查询。
- [ ] spaces 持久化:
  - [ ] create/delete/member add/remove 使用事务。
  - [ ] discoverability、plaintext_visible_services、owner、deleted 状态落库。
  - [ ] secret/invite_only/restricted 查询不泄露不可见 Space。
- [ ] invites 持久化:
  - [ ] token hash 存储。
  - [ ] expiry / max_uses / revoked_at。
  - [ ] resolve-space 使用 invite token 时写审计。

### 2.4 Message / Projection / Audit

- [ ] message/reaction/read-marker/state events 落库:
  - [ ] timeline position 单调生成。
  - [ ] event_id 幂等。
  - [ ] redact 后 pull/sync 不返回明文内容。
- [ ] projection recovery:
  - [ ] 启动时从 durable events 重建 `ProjectionState`。
  - [ ] 支持 reducer snapshot 快速加载。
  - [ ] snapshot frontier 与 repo head 不一致时回退 replay。
- [ ] audit log 持久化:
  - [ ] request_id、actor、device_id、space_id、operation_id、outcome 字段齐全。
  - [ ] cursor pagination。
  - [ ] high-risk endpoint 必须写 audit。

### 2.5 Transactional Write Path

- [ ] repo commit + projection event + audit log 同事务写入。
- [ ] commit append CAS 失败不写 projection/audit accepted。
- [ ] projection 更新失败时 repo commit 不可见。
- [ ] PostgreSQL integration test 覆盖:
  - [ ] successful transaction。
  - [ ] expected_head mismatch rollback。
  - [ ] duplicate commit same body 幂等。
  - [ ] duplicate commit different body conflict。

## 3. P0: Capability At Causal Frontier

目标: 授权由 reducer/frontier 决定, 不由当前内存 grant 快照或 handler 特判决定。

- [ ] capability operation 进入 operation stream:
  - [ ] grant。
  - [ ] delegate。
  - [ ] revoke。
  - [ ] approval。
- [ ] reducer 输出 effective capability state:
  - [ ] 按 HLC/actor_seq deterministic order。
  - [ ] revoke 覆盖旧 grant。
  - [ ] delegation depth 递减。
  - [ ] cycle detection。
- [ ] write path frontier check:
  - [ ] 每个业务 operation 声明 required action/resource。
  - [ ] frontier 不足返回 `stale_frontier`。
  - [ ] 未知 resource/action fail closed。
- [ ] resource selector grammar:
  - [ ] kind。
  - [ ] exact id。
  - [ ] prefix/pattern。
  - [ ] space scope。
  - [ ] child resource 递归规则。
- [ ] constraint schema:
  - [ ] `expires_at` / `not_before`。
  - [ ] fields allow/deny。
  - [ ] entity type allowlist。
  - [ ] visibility。
  - [ ] blob max bytes。
  - [ ] encryption required。
  - [ ] message edit window。
  - [ ] rate limit。
  - [ ] approval required。
  - [ ] requires claims。
- [ ] 未知 critical constraint 必须 fail closed。
- [ ] owner/member 默认权限改为 bootstrap grant 或显式 local policy。
- [ ] policy server 只能 deny/quarantine/review, 不能凭空授予 capability。
- [ ] conformance vectors:
  - [ ] grant before write accepted。
  - [ ] write before grant rejected。
  - [ ] revoke then write rejected。
  - [ ] delegated scope expansion rejected。
  - [ ] stale frontier rejected。

## 4. P0: Client Sync Correctness

目标: client 可以用 `since` 稳定增量同步, 重启后 cursor 仍有效, backfill gap 语义明确。

- [x] `next_batch` token 绑定 principal/device/service/filter/positions/expiry。
- [x] `since` 只返回增量。
- [x] token expiry 返回 `sync_token_expired`。
- [ ] sync positions 持久化:
  - [ ] per actor/device stream position。
  - [ ] per joined space timeline position。
  - [ ] to-device delivery position。
  - [ ] cursor 中 position 与数据库 position 双向校验。
- [ ] initial sync buckets:
  - [ ] join。
  - [ ] invite。
  - [ ] knock。
  - [ ] leave。
- [ ] joined Space payload:
  - [ ] timeline。
  - [ ] state。
  - [ ] state_after。
  - [ ] ephemeral。
  - [ ] account_data。
  - [ ] summary。
  - [ ] unread_notifications。
- [ ] deterministic timeline order:
  - [ ] causal_depth。
  - [ ] hlc。
  - [ ] actor_id。
  - [ ] actor_seq。
  - [ ] event_id。
- [ ] `timeline.limited=true`:
  - [ ] 返回 prev_batch。
  - [ ] backfill endpoint 可补 gap。
  - [ ] gap 过大时不伪装成完整 timeline。
- [ ] lazy member loading。
- [ ] filter validation:
  - [ ] limit 上限。
  - [ ] invalid filter 返回标准 error。
  - [ ] filter hash 纳入 cursor。
- [ ] `X-Contrix-Wait-For`:
  - [ ] 等待 repo/projection frontier。
  - [ ] timeout 返回 503 + retry metadata。
  - [ ] 已满足时响应头写 satisfied frontier。
- [ ] to-device ack:
  - [ ] 消息仅在 cursor ack 后标记 delivered。
  - [ ] 重复 sync 不丢未 ack 消息。
  - [ ] device revocation 后停止投递。
- [ ] sync conformance vectors 覆盖 initial、incremental、limited、expired、filter mismatch、to-device ack。

## 5. P0: Federation Security

目标: federation push/pull 可重启防 replay, 请求和 operation 都有可验证来源。

- [ ] HTTP Message Signatures:
  - [ ] 签名覆盖 method。
  - [ ] target URI。
  - [ ] authority。
  - [ ] content-digest。
  - [ ] origin service DID。
  - [ ] destination service DID。
  - [ ] created/expires。
- [ ] DID service binding:
  - [ ] origin DID Document service endpoint 必须包含发起服务。
  - [ ] destination 必须等于本服务 DID。
  - [ ] service delegation 覆盖目标 Space。
- [ ] operation verification:
  - [ ] 每个 operation 独立验签。
  - [ ] 每个 operation 按 causal frontier 验证 capability。
  - [ ] plaintext_visible_services 不允许越权转发。
- [ ] transaction persistence:
  - [ ] txn_id + origin 唯一。
  - [ ] 相同 body duplicate accepted。
  - [ ] 不同 body duplicate_conflict。
  - [ ] accepted operation ids 持久化。
  - [ ] 重启后 replay 仍被拦截。
- [ ] fork quarantine:
  - [ ] commit id conflict。
  - [ ] operation id conflict。
  - [ ] quarantine queue。
  - [ ] operator audit。
- [ ] pull authorization:
  - [ ] requester 具备 backfill capability。
  - [ ] history visibility 检查。
  - [ ] 不可见资源 not_found 不可区分。
- [ ] `verify-actor` 改为 challenge signature, 不作为公开 DID oracle。
- [ ] federation rate limit 与失败审计。

## 6. P1: Snapshot / Bootstrap

- [ ] reducer snapshot manifest:
  - [ ] `schema_profile_refs`。
  - [ ] `reducer_profile`。
  - [ ] `covers_frontier`。
  - [ ] `chunk_digests`。
  - [ ] `state_hash`。
  - [ ] `signed_by`。
  - [ ] `generator_signature`。
- [ ] snapshot chunk endpoint。
- [ ] chunk SHA-256 校验。
- [ ] state hash / Merkle root 生成。
- [ ] 客户端校验失败回退 repo replay 的测试。
- [ ] 首次加入流程文档和合同测试:
  - [ ] resolve service。
  - [ ] fetch invite/grants。
  - [ ] fetch snapshot manifest。
  - [ ] download chunks。
  - [ ] pull increments。
  - [ ] run reducer。
  - [ ] enter cursor subscription。

## 7. P1: Blob / Media

- [ ] blob metadata PostgreSQL 持久化:
  - [ ] blob_ref。
  - [ ] owner。
  - [ ] space_id。
  - [ ] content_type。
  - [ ] size。
  - [ ] sha256。
  - [ ] encrypted/plaintext 标记。
  - [ ] created_at。
- [ ] private blob access grants:
  - [ ] actor。
  - [ ] device。
  - [ ] space。
  - [ ] purpose。
  - [ ] expiry。
- [ ] HEAD/GET 不泄露不可见资源。
- [ ] Range / Content-Range 完整测试。
- [ ] quota:
  - [ ] single upload max bytes。
  - [ ] account total bytes。
  - [ ] per space total bytes。
- [ ] object-store backend adapter。
- [ ] signed redirect token。
- [ ] retention:
  - [ ] GC grace period。
  - [ ] legal hold。
  - [ ] unsafe media flag / scanning status。

## 8. P1: Device / E2EE / Push / Presence

- [ ] device pairing challenge。
- [ ] device authorization event。
- [ ] device revocation cascade:
  - [ ] session revoke。
  - [ ] key query 不返回 revoked device。
  - [ ] to-device queue 停止投递。
- [ ] device inventory endpoint。
- [ ] MLS groundwork:
  - [ ] KeyPackage publish/fetch/verify。
  - [ ] Welcome event。
  - [ ] Commit/Proposal event。
  - [ ] epoch mismatch recovery。
  - [ ] removed member fail closed。
- [ ] push rules priority groups:
  - [ ] override。
  - [ ] content。
  - [ ] room/space。
  - [ ] sender。
  - [ ] underride。
- [ ] push rules PostgreSQL 持久化。
- [ ] per Space unread/highlight counts。
- [ ] presence 持久化与多实例 fanout。
- [ ] typing ephemeral 跨实例广播。
- [ ] account data:
  - [ ] tags。
  - [ ] preferences。
  - [ ] ignored actors。
  - [ ] direct spaces。

## 9. P1: Index / Directory / Query

- [ ] query schema:
  - [ ] structured filters。
  - [ ] sort。
  - [ ] pagination cursor。
  - [ ] relation traversal。
  - [ ] full-text search for plaintext Space。
- [ ] authorization filtering per result。
- [ ] stale frontier reporting。
- [ ] explain/debug reducer state endpoint。
- [ ] view update / reconcile。
- [ ] graph/tree/gantt projection。
- [ ] organization create/update。
- [ ] organization membership。
- [ ] restricted query proof。
- [ ] signed link resolution。
- [ ] anti-enumeration tests:
  - [ ] actor search 不泄露 pairwise/private DID。
  - [ ] search users 仅限共同 Space / directory policy。
  - [ ] public/listed/restricted/unlisted/invite_only/secret 全组合测试。

## 10. P1: API Convention / Conformance

- [ ] `not_found` 对不存在与不可见保持不可区分。
- [x] 受保护 endpoint 禁止 query auth 的测试覆盖。
- [ ] 404 / 405 / 429 / 503 标准 envelope 全覆盖。
- [ ] per actor + per IP rate limit。
- [ ] high-risk endpoint 独立限流:
  - [ ] login。
  - [ ] federation。
  - [ ] blob upload。
  - [ ] directory resolve。
- [ ] structured tracing:
  - [ ] request_id。
  - [ ] actor。
  - [ ] device_id。
  - [ ] space_id。
  - [ ] operation_id。
  - [ ] commit_id。
- [ ] OpenAPI 3.1:
  - [ ] 服务生成 OpenAPI。
  - [ ] `/.well-known/contrix/openapi.yaml`。
  - [ ] operationId 等于 canonical `cx.*` operation id。
- [ ] conformance suites:
  - [ ] state resolution vectors。
  - [ ] redaction vectors。
  - [ ] capability vectors。
  - [ ] sync vectors。
  - [ ] snapshot vectors。
  - [ ] federation signature vectors。
  - [ ] privacy regression tests。

## 11. Definition of Done

任务只有同时满足以下条件才应标记完成:

- [ ] 代码实现完成。
- [ ] 相关 unit / HTTP / PostgreSQL integration 测试覆盖。
- [ ] 涉及协议语义时增加 conformance vector。
- [ ] Feature discovery 更新。
- [ ] README 或 profile 文档更新。
- [ ] 不依赖开发占位 proof、内存状态或硬编码 service DID, 除非任务明确属于 dev-only surface。
