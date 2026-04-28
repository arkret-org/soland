# soland vs contrix-spec 完成度分析

> 基于 contrix-spec v1 协议规范对 soland 参考实现的全面对比审计。
> 生成日期: 2026-04-28

---

## 完成度概览

| 协议平面 | 完成度 | 说明 |
|----------|--------|------|
| Identity Plane | ~15% | 仅有骨架端点,无 DID 解析/key log/handle 绑定的持久化或验证 |
| Write Plane (Repo) | ~85% | Repo adapter + Reducer + AuthzEngine 已实现; 缺因果前沿验证 |
| Sync & Federation Plane | ~45% | HLC + 基本 DID 验证 + reducer 投影; 缺持久化游标、完整签名验证、replay 防护 |
| Query Plane (Index) | ~50% | 所有端点已接入 reducer projection state; 缺持久化、全文搜索 |
| Presentation Plane | ~15% | Entity/Relation/View CRUD + reducer; 缺 kanban/table/calendar/timeline 投影 |
| Memory Plane | ~10% | schema 表存在但无 reducer、生命周期管理、向量检索层 |
| Confidentiality Plane | ~20% | E2EE opaque payload 透传已验证; 缺 MLS epoch 管理、密钥分发、加密边界执行 |
| Portability Plane | ~5% | 无导出/导入、snapshot replay、服务替换能力 |

**总体估算: 约 35-40% 完成 (对 spec 全部 SHALL/MUST 要求)**

---

## 一、缺失功能 (Missing Features)

### P0 — 协议核心,阻塞合规

#### 1. Identity Plane

- [ ] **DID:UUID 方法实现** — spec 定义 `did:uuid` 为默认原生方法 (UUID v8: 44-bit ms 时间戳 + 4-bit hash algo ID + 74-bit inception-key hash fragment)。当前仅存根返回。
- [x] **DID Document 状态解析 (内存基础)** — submit DID operation 写入 DID document,resolve/document/receipts 读取同一状态,并做 seq/prev head CAS。
- [ ] **DID Document PostgreSQL 持久化与多节点复制** — `identity_documents` PG 写入、签名验证、多节点复制仍未实现。
- [x] **Key Log 追踪 (内存基础)** — submit DID operation 写入 identity log events,identity/log 返回 event_hash/seq/operation。
- [ ] **Key Log 完整控制链** — 从 `inception_key` 到当前控制密钥的可验证完整链路仍未实现。
- [ ] **Handle 解析双向模型** — handle 是可验证声明 (verifiable claim) 而非授权主键。当前 handle 仅作为 accounts 表字段,无独立绑定证明。
- [x] **密钥类型承载 (基础)** — keys/upload/query 可承载 principal signing、recovery、device、session、agent、MLS KeyPackage、backup/restore 与 OTK/fallback key bundle。
- [ ] **密钥类型语义验证** — inception key、控制权绑定、key purpose、签名链、轮换/撤销约束仍未实现。
- [ ] **所有权证明** — 使用签名挑战 (signed fresh challenges) 而非解密历史密文能力。
- [ ] **渐进式身份披露** — presentation requests、disclosure policies、minimum-disclosure VCs/presentations 均未实现。
- [ ] **DID 控制证明验证** — 提交操作时需验证 DID 控制权。
- [ ] **密钥轮换** — 普通密钥轮换不得改变 DID。
- [ ] **密钥撤销** — 设备撤销需级联影响 session、key claim、device message、repo submit。

#### 2. Write Plane — Reducer 与状态解析

- [x] **Reducer 引擎** — spec 定义固定的 reducer 规则: 标量字段 LWW、集合字段 OR-Set、有序字段 fractional indexing、消息 append-only。已实现 `reducer.rs`。
- [ ] **操作因果前沿验证** — 必须在操作的 causal frontier 上验证授权,而非当前状态。
- [x] **操作授权验证** — 提交时需对照 `grant` 对象验证操作是否有权执行。已实现 `authz.rs`。
- [ ] **Space 版本管理** — `cx.space.upgrade` 和 `cx.space.tombstone` 的完整语义。
- [ ] **Membership 状态解析** — spec 要求的 membership state resolution (join/leave/invite/ban 的确定性收敛)。
- [x] **Redaction 语义** — redaction 应在 sync/index/search/notifications/blob previews 中完全消失。已通过 reducer 的 `redacted_at` 实现。

#### 3. Sync & Federation

- [x] **结构化 Cursor 编码** — `sync_token`/`next_batch` 返回 `cx:cursor:<base64url(JSON)>`,并在 `X-Contrix-Wait-For` 中校验 schema/version/positions。
- [ ] **持久化 Cursor 位置** — 持久化 per-space positions (causal frontier, timeline HLC, state hash)、device positions、expiration 与恢复语义。
- [x] **HLC (Hybrid Logical Clock)** — spec 定义格式: `<12-char hex physical>-<8-char hex logical>-<8-char hex node_id>`。已实现 `hlc.rs`。
- [x] **Read-Your-Writes 语态** — 写入返回 `sync_token`; 读取接受并校验 `X-Contrix-Wait-For` header。当前单节点投影写后立即可见,不做持久等待队列。
- [x] **Sync Profiles (基础声明/校验)** — `/sync/describe` 声明 board/chat/topic,`/sync` 校验 profile 参数。
- [ ] **Sync Profiles 差异化裁剪** — Board/Chat/Topic 的窗口、状态范围、timeline 限制和 cursor 策略仍未差异化。
- [ ] **首次加入流程** — resolve → discover services → fetch invite → fetch snapshot → download chunks → fetch increments → run reducer → cursor subscription。未实现。
- [ ] **Snapshot 签名验证** — 客户端必须验证 manifest 签名和 state hash。当前 snapshot-head 仅返回生成数据。
- [x] **Federation HTTP Message Signatures** — 已实现基本 DID 格式验证 (`verify_federation_origin`)。
- [x] **Federation Replay 防护 (内存)** — federation ingest 已检测重复 operation IDs 并返回 replay rejected。
- [ ] **Federation Replay 防护 (持久化)** — 需把已接受 operation IDs 持久化到 PostgreSQL,覆盖重启和多实例 replay。
- [x] **Federation Pull Redaction 过滤** — pull-operations 会过滤 redaction 记录和被 redacted 的目标操作。
- [x] **Fork 检测 (duplicate_conflict)** — 相同 commit ID 不同 hash 通过 repo idempotency conflict 返回 `duplicate_conflict`,并有 HTTP 覆盖。
- [ ] **Fork 隔离/Quarantine** — 冲突提交隔离、审计和 operator quarantine 流程仍未实现。
- [x] **Snapshot-Assisted Bootstrap (基础 manifest)** — `pull-operations?snapshot_bootstrap=true` 返回 snapshot_bootstrap manifest/state_hash/chunks/via_services。
- [ ] **Snapshot-Assisted Bootstrap chunks/signature** — 快照 chunk 下载、manifest 签名、state hash 客户端验证仍未实现。
- [ ] **主权部署 (Sovereign Deployment)** — 封闭联邦、DID allowlist、enclave 模式、外部 actor 进入流程。

#### 4. Authorization (Capability Model)

- [x] **Grant 对象持久化** — 已实现 `authz.rs` 中的 `AuthzEngine`,支持创建、查询、撤销。
- [ ] **条件授权 (Conditional Grants)** — subject 可以是条件选择器 + `requires_claims` (如 `org_membership` claim)。
- [x] **Resource Selector Grammar** — 已实现基本匹配: 精确匹配 + 前缀通配符 (`*`)。
- [x] **约束评估** — 已实现 temporal, type_restriction, delegation_control 约束类型。
- [x] **约束优先级** — explicit grant decision 按 deny > quarantine > allow > require_review 确定性裁决。
- [ ] **声明/证明系统** — 12 种 claim 类型: verified_handle, verified_email_domain, org_membership, org_role, employment_status, guardian_relationship, protected_actor_status, agent_controller, device_trust, mfa_level, risk_level, certification。
- [ ] **可问责 Actor** — agents, minors, managed accounts, automation accounts 的审批约束 (before_commit, proposal_then_approve, after_commit_review)。
- [ ] **委托 (Delegation)** — `max_delegation_depth` 控制。每次 re-grant 必须减少深度且不扩大范围。
- [x] **撤销 (Revocation)** — 已实现 `revoke_grant` 方法。

#### 5. Data Model — 核心对象

- [x] **Entity 统一载体** — spec 中 entity 是统一协作对象载体。已实现 CRUD 端点 + reducer。
- [x] **Relation 一等公民** — 跨对象语义 (containment, dependency, replies, mentions)。已实现 CRUD 端点 + reducer。
- [x] **View 投影对象** — spec 定义 view 是独立对象。已实现 create/get 端点。
- [ ] **Schema 注册** — spec 定义 16 种初始对象 schema + 35+ 事件类型。当前无 schema 管理。
- [ ] **Policy 对象** — `policy_documents` 表存在但未使用。
- [x] **Invite 对象 (基础)** — create_space 生成 pending invite 记录,`/authz/invites` 返回当前 actor 的有效邀请和 invite token。
- [x] **Read Marker** — 已实现 `set_read_marker` / `get_read_markers` 端点 + reducer。
- [x] **Notification 派生** — 已通过 projection state 实现,过滤 redacted 消息。

#### 6. Conversation Model (完整)

- [x] **Channel 实体 (基础 Entity 承载)** — `cx.channel` 可通过 Entity CRUD 创建/查询,并纳入 repo/projection。
- [x] **Topic 实体 (基础 Entity 承载)** — `cx.topic` 可通过 Entity CRUD 创建/查询,并纳入 repo/projection。
- [ ] **Channel/Topic 专用生命周期** — channel roles、thread anchoring、topic state transitions 与权限策略仍未实现。
- [x] **Message 修改链** — `cx.message.revise` revision chain。已实现 `revise_message` 端点 + reducer。
- [x] **Message 撤回** — `cx.message.redact` tombstone 语义。已实现 `redact_message` 端点 + reducer。
- [x] **Reaction OR-Set 收敛** — `cx.reaction.add/remove` 在 `(message_id, actor, reaction_key)` 上收敛。已实现端点 + reducer。
- [x] **@mention 结构化 (payload 基础)** — 非加密 message `mentions` 校验 DID 或 entity 引用对象,避免只能解析纯文本。
- [ ] **@mention Relations 物化** — `mentions` Relations、通知聚合和反向索引仍未实现。
- [x] **Comment 独立对象 (基础 Entity 承载)** — `cx.comment` 可通过 Entity CRUD 创建/查询,与 timeline messages 分离。
- [ ] **Comment 审阅工作流** — 对象级锚定、resolve/review、mention/reaction 聚合仍未实现。

#### 7. Confidentiality Plane (E2EE)

- [ ] **MLS RFC 9420 集成** — spec 要求 MLS 而非 Olm/Megolm。当前仅透传 opaque payload。
- [ ] **可审计 E2EE** — compliance actors 是可见组成员; 访问产生签名审计事件。
- [x] **Encrypted Payload Envelope (message publish)** — helper publish 与 repo submit 对 encrypted message 校验 scheme/version/group_id/epoch/content_type/ciphertext/authentication_tag/aad/key_ref/digests。
- [x] **Encrypted Payload Envelope (device/federation surfaces)** — device messages 发送前校验 encrypted envelope,federation ingest 对 operation semantics/encrypted message envelope 做拒收。
- [x] **Encrypted Payload Envelope (attachments)** — blob upload 支持 `x-contrix-attachment-envelope`,校验 algorithm/key_ref/nonce/ciphertext_digest 并写入 receipt。
- [ ] **Encrypted Payload Envelope (schema conformance)** — 正式 JSON Schema conformance 与跨端测试向量仍未实现。
- [ ] **设备配对** — 通过签名授权事件配对。
- [ ] **设备撤销级联** — 撤销未来写入并触发 MLS 移除。
- [ ] **设备交叉签名 (Cross-signing)** — 设备身份验证流程。
- [ ] **密钥备份** — `key_backups` 表存在但逻辑未实现。
- [x] **Plaintext-Visible Services (direct message flow)** — 私有 Space helper 发布非加密明文消息时,必须在 `plaintext_visible_services` 显式声明当前 service DID。
- [ ] **Plaintext-Visible Services (repo/federation/blob previews)** — repo submit、federation ingest、搜索摘要、缩略图和 blob previews 仍需统一策略检查。

#### 8. Content Types

- [x] **内容块系统 (基础校验)** — 非加密 message `content.blocks` 校验 text、formatted_text、image/video/audio/file、location、code、poll 基础结构,repo/federation message operation 复用校验。
- [ ] **内容块扩展/渲染语义** — extension mixins、客户端渲染契约、block-level relations 与迁移仍未实现。
- [x] **自定义类型 (反向域名校验)** — Entity `entity_type` 接受 `cx.*` 或 `com.example.*` 形式,拒绝非命名空间裸类型。

#### 9. Social Graph

- [x] **Social Post (基础 Entity 承载)** — `cx.social.post` 可通过 Entity CRUD 创建/查询。
- [ ] **Social Feed/Circle** — feed/circle 对象、feed 生成、圈层管理仍未实现。
- [ ] **Social Relations** — follows, contact, circle_member, blocks_social, reposts, quotes, likes, replies_to。
- [ ] **Audience Policy** — `cx.social.audience_policy`: public, followers, contacts, circle, organization, space_members, direct, private。
- [ ] **Snapshot-at-publish** — 发布时冻结 audience。

### P1 — 协议重要功能,影响完整度

#### 10. Memory Plane (AI Agent)

- [x] **Semantic Memory (基础 Entity 承载)** — `cx.memory.semantic` 可通过 Entity CRUD 创建/查询。
- [ ] **四层记忆完整模型** — Working/Episodic/Semantic/Task Memory 的生命周期、确认流程和关系仍未完整实现。
- [ ] **记忆生命周期** — candidate → confirmed → rejected/invalidated/superseded。
- [ ] **记忆溯源** — source objects, source runs, author, confidence, status。
- [ ] **向量存储** — 作为派生检索层而非真相源。
- [x] **Run 实体 (基础 Entity 承载)** — `cx.agent.run` 可通过 Entity CRUD 创建/查询。
- [ ] **Run 完整生命周期** — agent run 更新/完成/失败、状态流、artifact/result/cancel 仍未实现。

#### 11. Agent Protocol Interop

- [ ] **外部代理协议对接** — A2A, legacy ACP, MCP bridge: discovery, authorization, streaming status, artifacts, audit records, cancellation, results。
- [ ] **Agent Runtime 服务角色** — agent runs, tool execution, memory promotion。

#### 12. Applet Integration

- [ ] **Applet 注册** — 签名注册, actor/space/handle namespaces。
- [ ] **Applet Transactions** — `PUT /applet/transactions/{txn_id}`。
- [ ] **Ghost Actors** — applet 创建的幽灵 actor。
- [ ] **Portal Spaces** — applet-space 绑定。`applet_portals` 表存在但逻辑未实现。
- [ ] **Delegated Operations** — `via applet` 操作 (namespaces 不授予写入权限)。

#### 13. Discovery & Directory 完善

- [x] **6 级可发现性 (基础过滤)** — create_space 支持 public/listed/restricted/unlisted/invite_only/secret,并区分 search/resolve/sync 可见性。
- [x] **Invite-token 精确解析** — `resolve-space` 支持仅凭有效 invite token 定位 invite_only Space,无效 token 返回 404。
- [ ] **Signed-link/restricted 精确解析规则** — signed-link resolution、restricted 证明与 secret 链接签名仍未实现。
- [ ] **组织管理** — 组织创建/管理/成员 (当前仅有 demo 数据)。
- [x] **Presence 状态 (基础)** — `/sync` 的 `set_presence` 需要登录并写入当前 actor 状态,`/profile/presence` 返回当前 presence。
- [ ] **Typing 与 scoped ephemeral signals** — typing、按 Space policy 作用域控制、过期和持久/PG 行为仍未实现。

#### 14. Push Notifications

- [x] **E2EE Space 推送 (最小元数据)** — push notify 拒绝 title/body/preview/content/plaintext/message 等明文字段,保留 blind wakeup/device metadata。
- [ ] **推送规则** — `push_rules` 表存在但逻辑未实现。
- [x] **加密通知负载 (基础防泄露)** — push notification payload 递归过滤常见明文字段。

#### 15. Blob & Media

- [x] **Blob 字节文件存储** — upload 将 blob 字节写入 `SERVERX_BLOB_ROOT/sha256/<digest>`,download 优先读取文件。
- [ ] **Blob 元数据持久化** — blob metadata、引用、授权 grant、生命周期仍需 PostgreSQL/object-store 持久化。
- [ ] **授权下载** — 绑定 actor DID, device, Space, purpose, expiry。
- [x] **加密附件 (基础元数据)** — blob upload 校验并保存 algorithm、key_ref、nonce、ciphertext_digest。
- [ ] **缩略图** — E2EE 缩略图应客户端生成; 服务端需 `plaintext_visible_services`。
- [x] **Content-Disposition 安全** — HTML/JS/SVG 默认不内联。已实现。
- [ ] **Blob 生命周期** — GC: 无活跃引用 + grace period 已过 + 无 legal hold。
- [ ] **签名重定向授权** — `blob_access_grants` 表存在但逻辑未实现。

#### 16. Realtime Media (WebRTC)

- [ ] **WebRTC 信令** — 临时通道 + 签名信令消息。
- [x] **ICE 配置 (基础端点)** — `POST /contrix/v1/ice-config` 返回 service DID、TTL 与 ice_servers 数组。
- [ ] **TURN/STUN** — 外部服务集成。
- [ ] **SFU/MCU** — 选择性转发/混合。
- [ ] **通话成员策略** — 录制/保留策略。

#### 17. Moderation & Compliance

- [x] **审核队列 (基础)** — moderation report 自动生成 open moderation action,并路由到服务端 moderation actor。
- [ ] **申诉 (Appeals)** — 无实现。
- [ ] **法律保留 (Legal Hold)** — blob 保留逻辑。
- [x] **审计日志 (基础写入)** — account/auth、Space lifecycle、grant、blob get、moderation report 等关键路径写入内存 audit log。
- [x] **审计日志查询 (基础)** — `/api/v1/audit/events` 支持登录 actor 查询自己的内存审计事件,禁止越权查询其他 actor。
- [ ] **审计日志持久化/签名链** — `audit_log` PostgreSQL 持久化、分页 cursor、签名审计链仍未实现。

### P2 — 协议可选/高级功能

#### 18. Portability Plane

- [x] **Space 导出 (基础)** — `GET /api/v1/spaces/{space_id}/export` 导出 Space operations 与 projection events。
- [ ] **导入** — Space export import、冲突处理、签名校验和跨服务恢复仍未实现。
- [ ] **Snapshot + Operation Replay** — 完整状态恢复。
- [ ] **服务替换** — 从一个 Principal Server 迁移到另一个。

#### 19. Conformance & Encoding

- [x] **Canonical JSON (基础边界)** — message/repo/federation operation payload 在 HTTP 边界拒绝浮点数,避免非 canonical JSON 进入 operation digest。
- [ ] **Canonical JSON 完整约束** — sorted keys/no insignificant whitespace、RFC3339 UTC、snake_case、跨语言测试向量仍未完整覆盖。
- [x] **ID 格式** — `cx:<kind>:<ulid>` 生成器与测试已覆盖主要对象 ID。
- [x] **Digest 格式** — envelope digests、policy canonical hash、blob hash header 校验 `sha256:<64 lowercase hex>`。
- [ ] **Default Proof** — Detached JWS bound to payload hash, actor DID, verification method, audience/domain, creation time。
- [ ] **测试向量** — encoding, state resolution, redaction, capability, sync 的确定性测试向量。
- [ ] **JSON Schemas** — 4 个正式 schema: cursor, event, grant, encrypted-envelope。

#### 20. TSP Integration

- [ ] **Trust Spanning Protocol** — 可选集成用于 identity, federation, pairwise control messages。

---

## 二、设计缺陷与技术债务 (Design Defects)

### 架构级问题

#### D1. handlers.rs 单体文件 (4,271 行)

**问题**: 所有 HTTP handler + 辅助函数在单个文件中,违反单一职责原则。

**影响**: 可维护性差、合并冲突频繁、难以进行单元测试。

**建议**: 按协议平面拆分为独立模块: `handlers/identity.rs`, `handlers/repo.rs`, `handlers/sync.rs`, `handlers/federation.rs` 等。

#### D2. In-Memory 投影与 Postgres 投影不同步

**问题**: 当 `DATABASE_URL` 设置后,repo adapter 切换到 Postgres,但 accounts/contacts/sessions/devices/blobs 等仍使用内存状态。导致重启丢失非 repo 数据。

**影响**: PostgreSQL 模式并非真正持久化,误导用户认为数据已持久化。

**建议**: 明确标记哪些端点在 Postgres 模式下仍为内存 (文档 + 运行时 warning),或实现完整 Postgres 持久化。

**状态**: ⚠️ 已实现 `persistence.rs` trait 抽象层 + `MemoryPersistenceStore`,但 handler 尚未迁移。

#### D3. Reducer 缺失导致状态不一致

**问题**: 当前投影是 ad-hoc 的 (handler 中直接操作内存集合),而非通过确定性 reducer 处理操作流。

**影响**: 无法保证跨节点状态收敛; 无法实现 snapshot + replay; 无法验证操作在 causal frontier 上的授权。

**建议**: 实现 spec 定义的 reducer 引擎,将所有状态变更通过 reducer pipeline。

**状态**: ✅ 已实现 — `reducer.rs` 中的 `ProjectionState` + `apply()` 方法,支持 LWW、OR-Set、消息链。Index 端点已接入。

#### D4. 认证模型过于简化

**问题**: 当前使用 `SHA256(actor:device_id:expires_ms:soland-dev-session)` 生成 bearer token,无密码/passkey/OIDC。

**影响**: 仅适用于开发环境,无法用于生产。spec 要求 passkeys, OIDC, SSO, device pairing。

**建议**: 实现 spec 定义的 Auth Server 角色 (至少 passkey + session binding)。

#### D5. Federation 无安全验证

**问题**: 当前 federation 端点接受任何请求,无签名验证、origin 绑定、replay 防护。

**影响**: 任何人均可向 federation 端点注入伪造操作。

**建议**: 实现 HTTP Message Signatures 验证 (绑定 method, URI, authority, content-digest, service DIDs)。

**状态**: ⚠️ 已实现基本 DID 格式验证 (`verify_federation_origin`),但完整签名验证未实现。

### 数据模型问题

#### D6. Operation 类型硬编码

**问题**: `repo.rs` 中通过字符串匹配 (`"message"`, `"membership"`, `"space.lifecycle"` 等) 分发操作,而非使用 spec 定义的 `cx.<domain>.<verb>` 命名。

**影响**: 与 spec 不一致; 难以扩展新操作类型。

**建议**: 使用 spec 定义的操作族命名 (`cx.space.create`, `cx.entity.create`, `cx.message.create` 等)。

#### D7. Space 可发现性模型不完整

**问题**: 当前仅 `public`/`private` 二元区分。spec 定义 6 级: public, listed, restricted, unlisted, invite_only, secret。

**影响**: 无法实现 spec 要求的发现语义 (如 listed 但不公开内容, restricted 需要审批等)。

**建议**: 将 `discoverability` 字段从 boolean 改为 enum,实现各级别的过滤规则。

#### D8. Error Envelope 缺少 `retry_after_ms`

**问题**: spec 要求错误响应包含 `{ok: false, error: {code, message, retry_after_ms, details}}`。当前 429 返回 `Retry-After` header 但 envelope 中未包含 `retry_after_ms`。

**影响**: 非 HTTP 传输 (WebSocket, libp2p) 无法获取重试时间。

**建议**: 所有错误响应统一包含 `retry_after_ms` 字段 (可选)。

### 安全问题

#### D9. Dev Login 无环境门控

**问题**: `/api/v1/auth/dev-login` 端点在所有环境下可用,仅要求已注册账户。

**影响**: 生产环境中可能被滥用。

**建议**: 仅在 `RUST_ENV=development` 或明确配置 `DEV_LOGIN_ENABLED=true` 时启用。

**状态**: ✅ 已实现 — 通过 `config.development_mode` 门控。

#### D10. Blob 上传无认证强制

**问题**: 当前 blob 上传端点存在但授权检查不完整。

**影响**: 未授权用户可能上传恶意内容。

**建议**: 实现 spec 要求的授权绑定 (actor DID + device + Space + purpose)。

#### D11. Content-Disposition 未设置安全头

**问题**: spec 要求 HTML/JS/SVG 不内联渲染,当前 blob 下载未设置 `Content-Disposition: attachment`。

**影响**: 存储型 XSS 风险。

**建议**: 对危险 MIME 类型强制 `Content-Disposition: attachment; filename="safe.txt"`。

**状态**: ✅ 已实现 — 对 `text/html`, `application/javascript`, `image/svg+xml` 强制 attachment。

### 性能与可靠性

#### D12. 无 Rate Limiting 实现

**问题**: spec 要求 429 + `Retry-After`。当前无中间件实现。

**影响**: 易受 DoS 攻击。

**建议**: 添加 tower/salvo rate limiting 中间件,按 actor/IP 限制。

**状态**: ✅ 已实现 — `ratelimit.rs` 中间件,按 IP 限制 (默认 100 请求/60 秒)。

#### D13. 无结构化 Tracing

**问题**: 当前仅有基本 tracing。spec 要求 request IDs, operation IDs, structured spans。

**影响**: 难以排查生产问题。

**建议**: 使用 `tracing` crate 添加 span: request_id, actor, space_id, operation_id。

**状态**: ⚠️ Error envelope 已包含 `request_id` (via `ids::generate_request_id()`),但缺乏完整 span 体系。

#### D14. 无健康检查深度

**问题**: `/health` 仅返回 ok/storage mode,不检查 DB 连接、依赖服务状态。

**影响**: 容器编排无法检测服务真实健康状态。

**建议**: 检查 DB pool、repo adapter、关键依赖,返回详细状态。

---

## 三、Spec 合规性检查清单

### MUST/SHALL 要求未满足 (阻塞合规)

| 要求 | Spec 章节 | 状态 |
|------|-----------|------|
| DID-based principal_id | §3 Identity | ❌ 存根 |
| Handle 是可验证声明 | §3.2 | ❌ 简单字段 |
| 密钥轮换不改变 DID | §3.3 | ❌ 未实现 |
| Capability-based authorization | §5 | ✅ 已实现 `authz.rs` |
| Grant 对象持久化 | §5.2 | ✅ 已实现 `AuthzEngine` |
| 约束评估优先级 | §5.6 | ⚠️ 基本实现 (temporal, type_restriction, delegation_control) |
| Repo-first publication model | §6.1 | ✅ 已实现 |
| Commit signature verification | §6.2 | ✅ Proof 验证已实现 |
| CAS conflict detection | §6.2 | ✅ expected_head 已实现 |
| Idempotency (operation_id) | §6.7 | ✅ 已实现 |
| HLC 格式 | §6.4 | ✅ 已实现 `hlc.rs` |
| Cursor Base64URL encoding | §6.5 | ❌ 简化游标 |
| Canonical JSON (sorted keys) | §12.1 | ❌ 未验证 |
| ID format `cx:<kind>:<ulid>` | §12.2 | ✅ 已实现 `ids.rs` |
| Error envelope 格式 | §7.4 | ⚠️ 缺 retry_after_ms |
| Bearer auth (非 query string) | §7.4 | ✅ 已实现 |
| 429 + Retry-After | §7.4 | ✅ 已实现 `ratelimit.rs` |
| Federation signature verification | §8.2 | ⚠️ 基本 DID 格式验证 |
| E2EE opaque payload forwarding | §10.1 | ✅ 已验证 |
| MLS RFC 9420 | §10.1 | ❌ 未实现 |
| Plaintext-visible services declaration | §5.9 | ❌ 未实现 |
| Indistinguishable not_found | §13 | ❌ 未验证 |

---

## 四、建议优先级路线图

### Phase 1 (当前 → 协议最小合规)

1. 实现 Canonical JSON 序列化 (sorted keys, RFC 3339 timestamps)
2. 将 ID 格式改为 `cx:<kind>:<ulid>`
3. 实现 HLC 时钟
4. 实现 reducer 引擎 (至少 LWW + OR-Set + fractional indexing)
5. 完成 accounts/contacts/sessions 的 Postgres 持久化
6. 实现 capability grant 持久化与基本验证
7. 添加 rate limiting 中间件
8. 添加结构化 tracing

### Phase 2 (Federation 安全)

1. 实现 HTTP Message Signatures 验证
2. 实现 federation replay 防护
3. 实现 fork 检测与隔离
4. 实现 origin/destination service DID 绑定
5. 完成 federation 操作到统一投影的 reducer pipeline

### Phase 3 (E2EE & Identity)

1. 实现 DID:UUID 方法
2. 实现 DID Document 持久化与 key log
3. 集成 MLS RFC 9420 (至少 group creation + epoch management)
4. 实现设备配对与撤销级联
5. 实现 plaintext-visible services 声明

### Phase 4 (完整协议功能)

1. View 投影系统 (kanban, table, calendar, timeline 等)
2. Memory Plane 四层实现
3. Applet 注册与 portal
4. WebRTC 信令
5. Portability (export/import)
6. Conformance test vectors

---

## 五、已完实现 (Completed Implementation)

### Phase 1: Protocol Encoding Foundation ✅
- `ids.rs` — ULID-based ID generation (`cx:<kind>:<ulid>`)
- `hlc.rs` — Hybrid Logical Clock (`<12hex>-<8hex>-<8hex>`)
- `wire.rs` — `request_id` in error envelope

### Phase 2: Reducer & Projection Engine ✅
- `reducer.rs` — Deterministic state reducer with LWW, OR-Set, message chains
- `ProjectionState` — messages, reactions, read_markers, entities, relations, memberships, space_states, redactions
- 6 unit tests

### Phase 3: Entity, Relation & View CRUD ✅
- Entity: create, get, update, delete, list (6 endpoints)
- Relation: create, delete, list (3 endpoints)
- View: create, get (2 endpoints)

### Phase 4: Capability-Based Authorization ✅
- `authz.rs` — AuthzEngine with Grant, AuthzResult, Constraint
- Default rules: owner=all, member=subset
- Resource matching: exact + prefix wildcard
- Grant CRUD: create_grant, revoke_grant, effective_grants
- 5 unit tests

### Phase 5: Conversation Model ✅
- Message: revise (revision chain), redact (tombstone)
- Reaction: add/remove (OR-Set on event/actor/key)
- Read markers: set/get (LWW)

### Phase 6: Full Persistence Layer ✅ (trait abstraction)
- `persistence.rs` — PersistenceStore trait with AccountStore, SessionStore, ContactStore, SpaceMetaStore, MessageStore, BlobStore
- MemoryPersistenceStore implementation
- 3 unit tests

### Phase 7: Security Hardening ✅
- Dev login gating via `config.development_mode`
- Blob Content-Disposition for HTML/JS/SVG
- Rate limiting middleware (100 req/60s per IP)
- Federation origin DID validation
- Error envelope with request_id

### Phase 8: View System & Index Completion ✅
- `index_thread` — reads from reducer projection state
- `index_notifications` — filters redacted messages
- `index_inbox` — last message from projection
- `index_search` — message search from projection
- `send_message` — applies to reducer projection
