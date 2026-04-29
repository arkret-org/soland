# soland Contrix 协议落地 TODO

> 更新日期: 2026-04-29
> 目的: 以 `contrix-spec/zh` 为准, 对齐 `palpo` 这类完整协议服务器的工程成熟度, 将 soland 从 demo/reference server 推进到可声明 profile 的实现。

## SDK 侧接管/同步项

以下任务需要由 `E:\Works\contrix-dev\contrix-rust-sdk` 提供共享模型、
验证器、conformance vectors 或 client/server helper；soland 侧只保留
handler、PostgreSQL 落地、运行时策略和服务互操作验证。

- [ ] **[SDK] Canonical operation/event 注册表** — canonical `cx.*` kind、legacy migration adapter、operation envelope 字段、schema-driven semantic validation、内置操作 conformance vectors。
- [ ] **[SDK] Canonical JSON / digest / proof binding** — canonical bytes、operation/commit digest、proof payload hash、audience/domain/created_at binding、移除生产路径 `alg:none`/`dev-proof` 的共享验证器。
- [ ] **[SDK] DID identity / key log / service DID primitives** — `did:uuid`、resolver adapter、DID normalized view、key log、registry receipt signature、private DID proof gating、service DID endpoint 校验。
  - [x] SDK 已完成: `did:uuid` 结构化生成与 bit layout validation。
  - [x] SDK 已完成: `did:uuid`/`did:web`/`did:key`/`did:keri` resolver adapter trait。
  - [x] SDK 已完成: append-only key log verification 与从 inception 推导 current keys。
  - [ ] SDK 待完成: DID normalized service view、registry receipt signature、private DID proof gating、service DID endpoint 校验。
- [ ] **[SDK] 持久化抽象与测试套件** — repo/state/event/crypto/account/session/blob/audit/federation store traits、migration contract、transactional write conformance、projection rebuild helpers。
- [ ] **[SDK] Capability at causal frontier** — capability operations 进入 reducer、resource selector grammar、critical constraint fail-closed、delegation/claim/approval validation、policy server decision boundary。
  - [x] SDK 已完成: grant/delegate/revoke 进入 reducer state，并从 `SpaceState` 计算 active grants。
  - [x] SDK 已完成: causal frontier 上的 capability decision、revoke/delegate deterministic ordering、denied write negative vector。
  - [ ] SDK 待完成: 完整 resource selector grammar、critical constraint fail-closed、delegation depth/cycle、claim/approval validation、policy server decision boundary。
- [ ] **[SDK] Client sync correctness contract** — token binding、persistent positions、initial/incremental sync bucket、deterministic timeline order、limited/backfill gap、wait-for frontier、to-device ack semantics。
- [ ] **[SDK] Federation security helpers** — HTTP Message Signatures、origin/destination service binding、transaction idempotency、replay persistence contract、fork quarantine model、verify-actor challenge。
- [ ] **[SDK] Snapshot/bootstrap contract** — reducer snapshot manifest、chunk digest/state hash verification、bootstrap sequence、fallback-to-repo-replay behavior。
  - [x] SDK 已完成: reducer snapshot manifest/signature model、chunk digest、state hash/Merkle helper、fallback-to-repo-replay。
  - [ ] SDK 待完成: 完整 bootstrap sequence 与真实服务端 snapshot/sync interop。
- [ ] **[SDK] API convention helpers** — standard error envelope schema、query auth rejection helpers、rate/quota/tracing metadata types、not-found privacy semantics。
- [ ] **[SDK] Account/device/blob/push/WebRTC shared models** — session grant binding、device pairing/revocation, blob access grants, push rules, presence/typing/account-data types, ICE credential signature models。
- [ ] **[SDK] OpenAPI / schema / conformance generation** — JSON Schemas for cursor/event/operation/commit/grant/envelope/sync, OpenAPI 3.1 schema output, profile-specific conformance suites。
- [ ] **[SDK] Extended profile primitives** — agent runtime, applet bridge, social graph, sovereign deployment, portability/import-export, TSP integration shared types and validation hooks。

## 0. 当前判断

当前实现可以用于本地联调、协议面验证和客户端早期开发, 但还不能声明完整 Contrix v1 兼容。

现状:

- `cargo test` 已通过: 24 个单元测试 + 22 个 HTTP 合同测试。
- HTTP 路由面已经较广, 覆盖 account、identity、repo、sync、directory、index、authz、keys、device messages、blob、push、federation、WebRTC、moderation 等入口。
- 多数业务状态仍在内存 `AppState` 中, PostgreSQL migration 已有但尚未被 handler 全面使用。
- proof / DID / federation signature 仍以开发占位为主。
- reducer、authz、sync、snapshot、federation 只具备基础语义, 尚未满足 conformance profile 的 MUST 要求。

## 1. 目标 Profile 与完成状态

| Profile | 当前状态 | 阻塞项 |
| --- | --- | --- |
| `cx.profile.principal_server_repo_api.v1` | PARTIAL | 真实签名验证、canonical operation、schema validation、capability-at-frontier、持久化幂等 |
| `cx.profile.principal_server.v1` | PARTIAL | 持久 cursor、duplicate suppression、service binding、plaintext-visible enforcement 全链路、federation 安全 |
| `cx.profile.index_node.v1` | PARTIAL | 持久 reducer projection、query schema、auth filtering、stale frontier、wait-for 真实等待 |
| `cx.profile.identity_registry.v1` | PARTIAL | `did:uuid`、key log 验证、proof 验证、receipt 签名、method adapter |
| `cx.profile.blob_node.v1` | PARTIAL | 私有 blob 授权下载、metadata 持久化、quota、retention、thumbnail/preview 策略 |
| `cx.profile.applet_bridge.v1` | NOT STARTED | applet registration、namespace、transactions、ghost actor、portal space、signature verification |
| `cx.profile.agent_runtime.v1` | NOT STARTED | agent run lifecycle、tool audit、memory promotion、kill switch |
| `cx.profile.sovereign_deployment.v1` | NOT STARTED | service allowlist、closed federation、resolver pinning、external collaboration policy |

## 2. 已完成的基础能力

这些能力保留为当前基线, 后续任务应在此基础上替换 demo/内存/开发占位实现。

### 2.1 协议入口与基础工程

- [x] Salvo HTTP server 启动与 `/health`。
- [x] `/api/v1/server/describe` 基础服务发现。
- [x] 标准 error envelope, 包含 `request_id`。
- [x] 未知路径 / 错误 method 基础处理。
- [x] `dev-login` 已通过 `development_mode` 门控。
- [x] Query string auth material 拒绝。
- [x] IP 级 rate limit, 429 返回 `Retry-After` 与 `retry_after_ms`。
- [x] 基础 Dockerfile 与运行说明。

### 2.2 ID、HLC、Repo 基础

- [x] `cx:<kind>:<ulid>` ID 生成。
- [x] HLC 文本格式生成。
- [x] Memory repo adapter。
- [x] PostgreSQL repo adapter。
- [x] Commit append CAS。
- [x] `commit_id` / `operation_id` 基础幂等冲突检测。
- [x] Repo list/get/sync/submit 基础 endpoint。

### 2.3 Reducer 与投影基础

- [x] `ProjectionState` 基础 reducer。
- [x] message create / revise / redact。
- [x] reaction add/remove。
- [x] read marker。
- [x] entity create/update/delete。
- [x] relation create/delete。
- [x] membership join/leave 基础归约。
- [x] index thread/search/inbox/notification 读取 reducer projection。

### 2.4 协作对象与视图

- [x] Entity CRUD。
- [x] Relation CRUD。
- [x] View create/get。
- [x] list / kanban / table / calendar / timeline 基础投影。
- [x] `cx.channel`、`cx.topic`、`cx.comment`、`cx.memory.semantic`、`cx.agent.run` 作为 Entity 类型承载。
- [x] 自定义 Entity type 反向域名前缀校验。

### 2.5 Authz / Policy 基础

- [x] `AuthzEngine` 基础 grant create/revoke/check。
- [x] owner/member 默认规则。
- [x] explicit deny/quarantine/allow/review 优先级基础实现。
- [x] `/authz/check`、`/authz/effective-grants`、`/authz/invites`。
- [x] `/contrix/v1/check` policy check 基础响应。
- [x] policy documents 内存 CRUD。

### 2.6 Identity / Directory / Discovery 基础

- [x] DID document 内存提交与读取。
- [x] identity log 内存记录。
- [x] DID operation seq / prev head CAS 基础检查。
- [x] contacts request/respond/list。
- [x] Space create/delete/member add/remove。
- [x] discoverability 六级基础过滤: `public`、`listed`、`restricted`、`unlisted`、`invite_only`、`secret`。
- [x] invite token 精确解析。
- [x] directory search/resolve spaces。
- [x] directory organization/actor/user/handle demo projection。

### 2.7 E2EE / Device / Push / Blob / WebRTC 基础

- [x] Encrypted payload envelope 基础校验。
- [x] Device keys upload/query/claim 基础。
- [x] To-device message put/get 基础。
- [x] Push device register/unregister。
- [x] Push rules 内存 CRUD。
- [x] E2EE push payload 明文过滤。
- [x] Blob upload 写入本地文件。
- [x] Blob hash 校验。
- [x] Encrypted attachment metadata 校验。
- [x] 危险 MIME 类型强制 attachment。
- [x] WebRTC session/signals 内存基础。
- [x] `/contrix/v1/ice-config` 基础响应。

### 2.8 Federation / Snapshot / Audit 基础

- [x] Federation transaction / push / pull 基础端点。
- [x] Federation origin DID 格式检查。
- [x] Federation operation replay 内存检测。
- [x] Federation redaction pull 过滤。
- [x] Snapshot head 基础 manifest/state_hash。
- [x] Space export 基础。
- [x] Audit log 内存写入与当前 actor 查询。
- [x] Moderation report 基础队列。

## 3. P0: 协议核心合规

P0 的完成标准: 可以诚实声明 `principal_server_repo_api` 的核心子集, 并为 `principal_server` / `index_node` / `identity_registry` 打开 limited profile。

### 3.1 Canonical Operation / Event 模型

- [ ] 将所有 operation kind 统一为 `cx.*` 注册表命名。
  - [x] `message` -> `cx.message.create`。
  - [x] `message.revise` -> `cx.message.revise`。
  - [x] `redaction` -> `cx.message.redact` 或 `cx.redaction`。
  - [x] `entity.create/update/delete` -> `cx.entity.*`。
  - [x] `relation.create/update/delete` -> `cx.relation.*`。
  - [x] `membership` -> `cx.member.state` 或 `cx.membership.*` 兼容映射。
  - [x] `read_marker` -> `cx.read.marker`。
- [x] 增加 migration compatibility adapter, 只在明确 migration profile 下接受旧裸名。
  - [x] legacy kind -> canonical projection / reducer adapter。
  - [x] profile-gated legacy acceptance。
- [ ] 扩展 wire / SDK operation envelope:
  - [ ] `actor_id`
  - [ ] `kind`
  - [ ] `target_ref`
  - [ ] `causal.deps`
  - [ ] `causal.hlc`
  - [ ] `causal.actor_seq`
  - [ ] `authz_ref`
  - [ ] `proofs`
- [x] reducer dispatch 改为 canonical kind。
- [ ] `validate_operation_semantics` 改为 schema registry 驱动, 未注册事件 fail closed。
- [x] `supported_operations` 只声明 canonical operation id, 不声明产品私有别名。
- [ ] 给所有内置操作补 conformance vectors。

### 3.2 Canonical JSON / Hash / Signature

- [ ] 实现真正 canonical JSON bytes:
  - [ ] UTF-8。
  - [ ] object key Unicode code point 升序。
  - [ ] 无 insignificant whitespace。
  - [ ] number 边界约束。
  - [ ] RFC3339 UTC `Z` timestamp。
  - [ ] snake_case 字段名校验。
- [ ] Operation digest 使用 canonical bytes。
- [ ] Commit digest 使用 canonical commit-without-proofs bytes。
- [ ] Proof payload_hash 必须等于 canonical digest。
- [ ] Default proof 绑定:
  - [ ] actor DID。
  - [ ] verification method。
  - [ ] payload hash。
  - [ ] audience / domain。
  - [ ] created_at。
- [ ] 移除生产路径的 `alg: none` / `dev-proof`。
- [ ] 增加 signature binding conformance tests。

### 3.3 DID Identity 与 Key Log

- [ ] 实现 `did:uuid`。
  - [ ] UUID v8 bit layout。
  - [ ] 44-bit Unix ms。
  - [ ] 4-bit hash algorithm id。
  - [ ] 74-bit inception key hash fragment。
  - [ ] 大端填充。
  - [ ] 非法 method id / hash mismatch 拒绝。
- [ ] DID resolver method adapter:
  - [ ] `did:uuid`。
  - [ ] `did:web` limited profile。
  - [ ] `did:key` test/temporary profile。
- [ ] DID Document normalized view:
  - [ ] raw document hash。
  - [ ] current control keys。
  - [ ] service bindings。
  - [ ] method evidence。
- [ ] Key log 验证:
  - [ ] inception。
  - [ ] rotate。
  - [ ] recover。
  - [ ] deactivate。
  - [ ] seq 单调。
  - [ ] append-only。
  - [ ] 当前 key 可从 inception key 推导。
- [ ] `submit-did-operation` 从“proof 非空”升级为真实 DID control proof 验证。
- [ ] Registry receipt 签名:
  - [ ] 绑定 DID。
  - [ ] seq。
  - [ ] head_event_hash。
  - [ ] registry service DID。
  - [ ] audience。
  - [ ] created_at。
- [ ] `identity/resolve` 对 private / pairwise DID 增加 proof gating。

### 3.4 Service DID 与配置一致性

- [x] 全面使用 `SERVERX_SERVICE_DID` / `config.service_did`, 移除硬编码 `did:web:soland.local`。
- [x] HLC node id 使用配置 service DID。
- [x] `server/describe`、`identity/describe`、`sync/describe`、`directory/describe`、`index/describe`、blob receipt、snapshot signature 均使用配置 service DID。
- [ ] 增加 service DID 格式与 DID document service endpoint 校验。
- [x] Feature discovery 按实际能力声明 limited profiles。

### 3.5 Durable Storage 贯穿业务状态

- [ ] 为 `PersistenceStore` 增加 PostgreSQL 实现。
- [ ] `AppState` 注入 store trait, 不直接暴露大量 `Arc<Mutex<...>>` 作为生产状态源。
- [ ] 迁移 account:
  - [ ] register。
  - [ ] me。
  - [ ] disabled / lifecycle。
  - [ ] handle binding。
- [ ] 迁移 session:
  - [ ] token persistence。
  - [ ] expiry。
  - [ ] revoked_at。
  - [ ] device binding。
- [ ] 迁移 identity:
  - [ ] documents。
  - [ ] log events。
  - [ ] receipts。
- [ ] 迁移 contacts。
- [ ] 迁移 spaces / members / aliases / invites。
- [ ] 迁移 events / state events / projection events。
- [ ] 迁移 entities / relations / reactions / read markers。
- [ ] 迁移 devices / device keys / OTK / fallback keys / device messages。
- [ ] 迁移 blobs metadata 与 access grants。
- [ ] 迁移 push devices / push rules。
- [ ] 迁移 policy documents / capability grants / policy decisions。
- [ ] 迁移 moderation reports/actions。
- [ ] 迁移 audit log。
- [ ] 迁移 federation transactions / memberships / accepted operation ids。
- [ ] 迁移 sync positions。
- [ ] 服务启动时从 durable repo/events 重建 projection 或加载 reducer snapshot。
- [ ] 所有写路径使用数据库事务保证 repo、projection、audit 一致。

### 3.6 Capability At Causal Frontier

- [ ] Grant / delegate / revoke 本身进入 operation stream。
- [ ] 授权状态由 reducer 顺序收敛, 不再只查当前内存 grant。
- [ ] 业务 operation 接收时按 causal frontier 验证有效 grant。
- [ ] 若 frontier 不足, 返回 `stale_frontier` 或 fail closed。
- [ ] Resource selector grammar 完整实现:
  - [ ] kind。
  - [ ] id / pattern。
  - [ ] space scope。
  - [ ] child resource 递归规则。
- [ ] Constraint schema 完整实现:
  - [ ] `expires_at` / `not_before`。
  - [ ] fields allow/deny。
  - [ ] entity / memory type allow。
  - [ ] visibility。
  - [ ] blob max bytes。
  - [ ] encryption required。
  - [ ] message edit window。
  - [ ] rate limit。
  - [ ] approval required。
  - [ ] accountability required。
  - [ ] requires claims。
- [ ] 未知 critical constraint 必须 fail closed。
- [ ] Delegation:
  - [ ] max depth 递减。
  - [ ] 不得扩大 scope/action。
  - [ ] cycle detection。
- [ ] Claim / attestation 验证:
  - [ ] issuer trust。
  - [ ] subject。
  - [ ] proof。
  - [ ] effective time。
  - [ ] revocation。
- [ ] Approval / proposal 模式。
- [ ] owner/member 默认权限改为 bootstrap grant 或明确 local policy, 避免协议层隐式授权。
- [ ] Policy server 只能 deny/quarantine/review, 不能凭空授予 capability。

### 3.7 Client Sync 正确性

- [ ] `next_batch` token 绑定:
  - [ ] principal id。
  - [ ] device id。
  - [ ] service id。
  - [ ] filter hash。
  - [ ] stream positions。
  - [ ] expiry。
- [ ] 持久化 sync positions。
- [ ] 实现 `since` 语义, 只返回增量。
- [ ] 初始同步分桶:
  - [ ] join。
  - [ ] invite。
  - [ ] knock。
  - [ ] leave。
- [ ] 每个 joined Space 返回:
  - [ ] timeline。
  - [ ] state。
  - [ ] state_after。
  - [ ] ephemeral。
  - [ ] account_data。
  - [ ] summary。
  - [ ] unread_notifications。
- [ ] Deterministic timeline order:
  - [ ] causal_depth。
  - [ ] hlc。
  - [ ] actor_id。
  - [ ] actor_seq。
  - [ ] event_id。
- [ ] `timeline.limited=true` 与 backfill gap 语义。
- [ ] lazy member loading。
- [ ] filter limits 与 invalid filter errors。
- [ ] `X-Contrix-Wait-For` 实现真实 frontier 等待 / timeout。
- [ ] To-device delivery 与 next_batch ack 语义明确化。
- [ ] token expiry 返回 `sync_token_expired`。
- [ ] sync conformance vectors。

### 3.8 Federation 安全与收敛

- [ ] HTTP Message Signatures:
  - [ ] method。
  - [ ] target URI。
  - [ ] authority。
  - [ ] content-digest。
  - [ ] origin service DID。
  - [ ] destination service DID。
  - [ ] created/expires。
- [ ] 验证 origin/destination 与 DID Document service endpoint 一致。
- [ ] 验证 destination 等于本服务 DID。
- [ ] 验证 Space policy / service delegation 覆盖 federation 目的。
- [ ] 每个 operation 独立验签。
- [ ] 每个 operation 按 causal frontier 验证 capability。
- [ ] 持久化 federation transaction 与 accepted operation ids。
- [ ] 重启与多实例后仍能 replay 防护。
- [ ] `txn_id` 幂等:
  - [ ] 相同 body duplicate accepted。
  - [ ] 不同 body duplicate_conflict。
- [ ] Fork 检测:
  - [ ] commit id conflict。
  - [ ] operation id conflict。
  - [ ] quarantine queue。
  - [ ] operator audit。
- [ ] Pull operations 授权:
  - [ ] requester backfill capability。
  - [ ] history visibility。
  - [ ] plaintext_visible_services。
- [ ] `verify-actor` 真实 challenge signature 验证, 不得作为公开 DID oracle。
- [ ] 联邦失败审计与 rate limit。

### 3.9 Snapshot 与 Bootstrap

- [ ] Reducer snapshot manifest:
  - [ ] `schema_profile_refs`。
  - [ ] `reducer_profile`。
  - [ ] `covers_frontier`。
  - [ ] `chunk_digests`。
  - [ ] `state_hash`。
  - [ ] `signed_by`。
  - [ ] `generator_signature`。
- [ ] Snapshot chunk 下载 endpoint。
- [ ] Chunk SHA-256 校验。
- [ ] State hash / Merkle root 生成。
- [ ] 客户端校验失败回退到 repo replay 的测试。
- [ ] 首次加入流程:
  - [ ] resolve。
  - [ ] discover services。
  - [ ] fetch invite/grants。
  - [ ] fetch snapshot manifest。
  - [ ] download chunks。
  - [ ] pull increments。
  - [ ] run reducer。
  - [ ] enter cursor subscription。

### 3.10 API Conventions / Anti-Abuse

- [ ] `not_found` 对不存在与不可见保持不可区分。
- [ ] 受保护 endpoint 禁止 query auth 的测试覆盖。
- [ ] 404 / 405 / 429 / 503 标准 envelope 全覆盖。
- [ ] Per actor + per IP rate limit。
- [ ] High-risk endpoint 独立限流:
  - [ ] login。
  - [ ] identity submit。
  - [ ] federation。
  - [ ] blob upload。
  - [ ] directory resolve。
- [ ] Quota:
  - [ ] blob size。
  - [ ] account total storage。
  - [ ] operations per window。
  - [ ] devices / OTK。
- [ ] Structured tracing:
  - [ ] request_id。
  - [ ] actor。
  - [ ] device_id。
  - [ ] space_id。
  - [ ] operation_id。
  - [ ] commit_id。
- [ ] CORS 配置从 placeholder 变为真实策略。

## 4. P1: 重要产品能力与完整协议面

P1 的完成标准: 能支撑真实多用户、多设备、持久化、可恢复的协作场景。

### 4.1 Account / Auth / Device

- [ ] Passkey 登录。
- [ ] OIDC / SSO 登录。
- [ ] Session grant 绑定 DID / device。
- [ ] Refresh token / soft logout。
- [ ] Account lifecycle:
  - [ ] disable。
  - [ ] lock。
  - [ ] erase。
  - [ ] session revocation。
- [ ] Device pairing challenge。
- [ ] Device authorization event。
- [ ] Device revocation cascade。
- [ ] Device inventory。
- [ ] Dehydrated device / recovery path。

### 4.2 Handle / Claims / Progressive Disclosure

- [ ] Handle 双向验证。
- [ ] `verified_handle` claim。
- [ ] `verified_email_domain` claim。
- [ ] `org_membership` / `org_role` claim。
- [ ] Presentation request。
- [ ] Disclosure policy。
- [ ] Pairwise/private DID 可见性控制。
- [ ] Claim revocation fail-closed。

### 4.3 MLS E2EE

- [ ] MLS RFC 9420 group state。
- [ ] KeyPackage publish / fetch / verify。
- [ ] Welcome event。
- [ ] Commit / Proposal event。
- [ ] Epoch mismatch recovery。
- [ ] Removed member fail-closed。
- [ ] Encrypted payload schema conformance。
- [ ] Encrypted attachment schema conformance。
- [ ] Secret storage。
- [ ] Key backup。
- [ ] Cross-signing / device trust。
- [ ] Local plaintext search for encrypted content guidance。

### 4.4 Blob / Media

- [ ] Blob metadata PostgreSQL 持久化。
- [ ] Private blob access grants。
- [ ] Download 授权绑定:
  - [ ] actor。
  - [ ] device。
  - [ ] Space。
  - [ ] purpose。
  - [ ] expiry。
- [ ] HEAD/GET 不泄露不可见资源。
- [ ] Range / Content-Range 完整测试。
- [ ] Thumbnail 策略:
  - [ ] E2EE thumbnail client generated。
  - [ ] plaintext thumbnail requires plaintext-visible service。
- [ ] Preview policy。
- [ ] Object-store backend。
- [ ] Signed redirect token。
- [ ] GC grace period。
- [ ] legal hold。
- [ ] unsafe media flag / scanning status。

### 4.5 Index / Query / View

- [ ] `query-schema.md` 完整实现。
- [ ] Structured filters。
- [ ] Relation query。
- [ ] Space hierarchy。
- [ ] Thread query by topic/message anchor。
- [ ] Notification materialization。
- [ ] Inbox materialization。
- [ ] Full-text search for plaintext Space。
- [ ] Encrypted Space local-only / TEE profile 标识。
- [ ] Authorization filtering per result。
- [ ] Stale frontier reporting。
- [ ] Explain/debug reducer state endpoint。
- [ ] View update / reconcile。
- [ ] Graph / tree / gantt projection。

### 4.6 Directory / Organization / Discovery

- [ ] Organization create/update。
- [ ] Organization membership。
- [ ] Organization DID governance / service delegation。
- [ ] Restricted query proof。
- [ ] Signed link resolution。
- [ ] Secret link signature。
- [ ] Anti-enumeration regression tests。
- [ ] Actor search 不泄露 pairwise/private DID。
- [ ] Search users 仅限共同 Space / directory policy。
- [ ] Public/listed/restricted/unlisted/invite_only/secret 全组合测试。

### 4.7 Push / Presence / Typing / Account Data

- [ ] Push rules 按 Matrix-like priority 分组:
  - [ ] override。
  - [ ] content。
  - [ ] room/space。
  - [ ] sender。
  - [ ] underride。
- [ ] Push rules PostgreSQL 持久化。
- [ ] Per Space unread/highlight counts。
- [ ] Push gateway integration adapter。
- [ ] Presence 持久化与多实例 fanout。
- [ ] Typing ephemeral 跨实例广播。
- [ ] Account data:
  - [ ] tags。
  - [ ] preferences。
  - [ ] ignored actors。
  - [ ] direct spaces。

### 4.8 Moderation / Audit / Compliance

- [ ] Moderation action workflow。
- [ ] Appeals。
- [ ] Report visibility 仅 moderator 可见。
- [ ] Policy deny/quarantine/review 与 moderation queue 贯通。
- [ ] Audit log PostgreSQL 持久化。
- [ ] Audit cursor pagination。
- [ ] Audit signature chain。
- [ ] Break-glass workflow。
- [ ] Legal hold。
- [ ] Compliance actor E2EE access audit。

### 4.9 WebRTC / Media Service

- [ ] WebRTC sessions PostgreSQL 持久化。
- [ ] Multi-device participant。
- [ ] Expiry cleanup task。
- [ ] Cross-instance signal fanout。
- [ ] TURN/STUN provider integration。
- [ ] ICE credential signature。
- [ ] Call/media capability check。
- [ ] Recording / retention policy。
- [ ] SFU/MCU profile declaration。

### 4.10 Schema Registry / OpenAPI / Conformance

- [ ] 生成正式 JSON Schemas:
  - [ ] cursor。
  - [ ] event。
  - [ ] operation。
  - [ ] commit。
  - [ ] grant。
  - [ ] encrypted-envelope。
  - [ ] client-sync-response。
- [ ] 标准 schema registry 覆盖 `schema-registry.md` 全部 core schema。
- [ ] 服务生成 OpenAPI 3.1。
- [ ] `/.well-known/contrix/openapi.yaml`。
- [ ] OpenAPI operationId 等于 canonical `cx.*` operation id。
- [ ] Conformance suite:
  - [ ] encoding vectors。
  - [ ] state resolution vectors。
  - [ ] redaction vectors。
  - [ ] capability vectors。
  - [ ] sync vectors。
  - [ ] snapshot vectors。
  - [ ] federation signature vectors。
  - [ ] privacy regression tests。

## 5. P2: 扩展 Profile

P2 的完成标准: 在核心 profile 稳定后扩展到 agent、applet、social、sovereign 等高价值场景。

### 5.1 Agent Runtime

- [ ] Agent principal / delegated actor。
- [ ] Agent run lifecycle:
  - [ ] create。
  - [ ] update。
  - [ ] complete。
  - [ ] fail。
  - [ ] cancel。
- [ ] Tool execution audit envelope。
- [ ] Memory candidate / confirmed / rejected / invalidated / superseded。
- [ ] Memory provenance:
  - [ ] source objects。
  - [ ] source runs。
  - [ ] author。
  - [ ] confidence。
  - [ ] status。
- [ ] Vector index as derived retrieval layer。
- [ ] Approval constraint for high-risk agent actions。
- [ ] Kill switch / revocation check。
- [ ] A2A / ACP / MCP bridge session metadata。

### 5.2 Applet Bridge

- [ ] Signed applet registration。
- [ ] Namespace declaration。
- [ ] Namespace conflict detection。
- [ ] `/api/v1/applet/ping`。
- [ ] `/api/v1/applet/describe`。
- [ ] `PUT /api/v1/applet/transactions/{txn_id}`。
- [ ] Applet transaction idempotency。
- [ ] Query actor endpoint。
- [ ] Query space endpoint。
- [ ] Third-party users / locations。
- [ ] Ghost actor accountability metadata。
- [ ] Portal Space mapping。
- [ ] Per-Space applet capability。
- [ ] Applet health and lag metrics。
- [ ] Unauthorized namespace hit must not grant write permission。

### 5.3 Social Graph

- [ ] Feed object。
- [ ] Circle object。
- [ ] Follow/contact/circle_member relations。
- [ ] Block social relation。
- [ ] Repost / quote / like / reply relations。
- [ ] Audience policy:
  - [ ] public。
  - [ ] followers。
  - [ ] contacts。
  - [ ] circle。
  - [ ] organization。
  - [ ] space_members。
  - [ ] direct。
  - [ ] private。
- [ ] Snapshot-at-publish。
- [ ] Circle feed E2EE / visibility tests。

### 5.4 Sovereign Deployment

- [ ] Organization DID controlled service delegation。
- [ ] Service DID allowlist。
- [ ] Closed federation default。
- [ ] Private directory default。
- [ ] Resolver trust domain pinning。
- [ ] Controlled collaboration Space。
- [ ] Restricted / invite-only external join。
- [ ] External device approval。
- [ ] MLS epoch rotation after external removal。
- [ ] External Applet / Agent / transport allowlist。
- [ ] Data classification labels。
- [ ] Import/export review metadata。
- [ ] Offline witness receipts。
- [ ] Hardware-backed service keys。

### 5.5 Portability / Migration

- [ ] Full Space export:
  - [ ] raw operations。
  - [ ] commits。
  - [ ] snapshots。
  - [ ] blobs manifest。
  - [ ] grants。
  - [ ] audit metadata。
- [ ] Import validation:
  - [ ] signatures。
  - [ ] hashes。
  - [ ] reducer replay。
  - [ ] conflict handling。
- [ ] Service replacement flow。
- [ ] Principal Server migration guide。
- [ ] Cross-service recovery tests。

### 5.6 TSP Integration

- [ ] TSP optional trust binding。
- [ ] Pairwise control messages。
- [ ] Federation trust policy hook。
- [ ] Identity registry witness integration。

## 6. 建议执行顺序

### Milestone 1: Canonical Core

- [ ] Canonical operation/event kind。
- [ ] Canonical JSON/hash。
- [ ] Real commit proof verification。
- [x] Config service DID。
- [x] Feature discovery 降级为真实 limited profile。

### Milestone 2: Durable Server

- [ ] PostgreSQL PersistenceStore。
- [ ] Account/session/identity/space/message/device/blob/policy/audit/federation 状态迁移。
- [ ] Projection recovery。
- [ ] Transactional write path。

### Milestone 3: Authz + Reducer Correctness

- [ ] Capability operations enter reducer。
- [ ] Authorization at causal frontier。
- [ ] Constraint fail-closed。
- [ ] Delegation/claim/approval 基础。
- [ ] State-resolution conformance vectors。

### Milestone 4: Sync + Federation

- [ ] Persistent sync tokens/positions。
- [ ] Initial/incremental sync correctness。
- [ ] Backfill gap semantics。
- [ ] HTTP Message Signatures。
- [ ] Persistent replay/idempotency/quarantine。

### Milestone 5: Identity + Device + Blob

- [ ] `did:uuid`。
- [ ] DID key log。
- [ ] Device pairing/revocation。
- [ ] MLS envelope/profile groundwork。
- [ ] Blob authorization and metadata durability。

### Milestone 6: Conformance and Profile Declaration

- [ ] OpenAPI generation。
- [ ] Conformance vectors。
- [ ] Privacy regression tests。
- [ ] Profile-specific README / feature matrix。
- [ ] CI jobs for unit, HTTP, PostgreSQL integration, conformance.

## 7. Definition of Done

一个任务只有同时满足以下条件才应标记为完成:

- [ ] 代码实现完成。
- [ ] 相关 HTTP / unit / integration 测试覆盖。
- [ ] 若涉及协议语义, 增加 conformance vector 或明确说明不适用。
- [ ] Feature discovery 更新。
- [ ] README 或实现 profile 文档更新。
- [ ] 不依赖开发占位 proof、内存状态或硬编码 service DID, 除非任务明确属于 dev-only surface。
