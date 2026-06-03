# soland 安全审计报告：安全漏洞与需加强项

> 被审项目：`D:/Works/contrix-dev/soland`（约 12.7 万行，主服务端）。
> 仅做防御性审查。所有 `相对路径:行号` 均以 `soland/` 为根，已逐条重新打开核对。

## 审查范围

本轮聚焦“安全相关 + 公开 wire/HTTP 入口”模块，按优先级实际通读/检索了以下路径：

- 全局路由装配与中间件链：`src/routing/mod.rs`（重点 75-184 行中间件 hoop 链、CORS、404/405）。
- 认证 / 会话：`src/routing/identity/auth.rs`（dev-login、session-grant、OAuth introspection、会话校验流水线、token 派生）。
- 授权引擎：`src/authz.rs`（capability check / 委派 / decision 优先级）、`src/routing/policy_gate.rs`（远程 policy server 合流、fail-closed）。
- 签名 / canonical bytes：`src/jws_verify.rs`、`src/routing/federation/federation.rs`（HTTP Message Signature、relay 内层签名、verify-actor、anchors）、`src/routing/identity/recovery.rs`（恢复策略/回执/会话证明签名）。
- E2EE / 密钥处理：`src/routing/identity/key_backup.rs`（key backup CRUD、KDF floor、删除所有权证明）。
- SSRF / egress：`src/security.rs`、`src/did_resolver_chain.rs`。
- 限流 / 反枚举：`src/ratelimit.rs`。
- Blob / 路径穿越 / 文件下载：`src/routing/interop/blob.rs`。
- 配置安全姿态：`src/config.rs`（CORS、dev-mode、bearer 加载）。
- unsafe 审查：全仓 `grep unsafe`（仅 `set_var/remove_var`，见下）。
- 时序 / 常量时间比较：全仓 `grep subtle|constant_time|ct_eq`（无命中，见下）。
- conformance 测试面 gating：`src/routing/conformance/{mod,handlers}.rs`。

复验命令：
- `rg -n "unsafe" soland/src --glob '!*test*'`
- `rg -n "subtle|constant_time|ct_eq|ConstantTime" soland/src`
- `rg -n "development_mode" soland/src`
- 路由文件逐个 Read 核对（见各问题证据行号）。

**未覆盖 / 覆盖较浅（避免“已全覆盖”错觉）**：reducer 状态机与 CRDT lattice（`src/reducer*`、`src/state/`）的授权投影只做了入口检索，未逐行复核；MLS 生命周期 `src/routing/mls.rs`、`src/reducer/mls.rs` 仅检索未通读；moderation/erasure 真正生效性（`src/gc.rs`、`src/routing/federation/erasure_fanout.rs`、`tombstone_projection_event_for_erased_actor`）仅做了入口确认，未完整验证“redaction 是否在所有读路径生效”；media/foci（`webrtc.rs`、`rtc/token`）、push、agent 这几条线未深入；依赖已知漏洞（`Cargo.lock` / `deny.toml`）未做 advisory 比对。SDK 侧 `contrix-rust-sdk`（`jws`、`canonical`、`DidWebResolver`）只在边界处引用，未审 SDK 内部实现。

---

## 结论摘要

本轮共保留 **8** 条有效问题，最高严重级别 **P1**：

- **P1 ×2**：(1) 联邦 `pull-operations` / `space-members` / `anchors` (GET) 三个读端点完全无认证、无来源校验、无 denylist，泄露操作流与成员名单并可被任意客户端拉取；(2) `federation_anchors_push` 接受任意来源、无 HTTP 签名校验地写入本地 Anchor DAG（finality 前沿注入）。
- **P2 ×3**：(3) blob presign / direct-serve 的 T11 fail-closed 闸门（legal_hold / redacted / actor_private）因策略值被硬编码为 `false`/`null` 而**永不触发**，redaction 未在 blob 下载路径生效；(4) egress SSRF 守卫存在 DNS rebinding TOCTOU（校验解析 IP 后未把 IP 钉入实际请求，reqwest 在 connect 时重新解析）；(5) presign 直发路径在“无 session（presigned）”分支跳过可见性检查，presign 令牌不绑定接收者。
- **P3 ×3**：(6) debug 构建无条件开放 conformance 端点（含确定性签名 oracle，虽非真实身份密钥）；(7) 多处密钥/凭据/证明比较使用非常量时间 `==`（presign token、dev 删除证明、federation 幂等键）；(8) `recovery_policy_put` / 多个恢复端点不校验 `session.actor == principal_id`（依赖签名兜底，权限隔离偏弱）。

---

## 问题 1：联邦只读端点（pull-operations / space-members / anchors-pull）完全无认证与来源校验

**严重级别**：P1

**证据**：
- 路由注册（无任何 auth/签名 hoop）：`src/routing/federation/mod.rs:33-35`（`federation/pull-operations` → GET）、`:49`（`federation/space-members` → GET）、`:55-56`（`federation/anchors` → GET）。
- 全局中间件链只挂了 metrics / max-size / state-inject / rate-limiter / CORS，无统一认证：`src/routing/mod.rs:101-108`。`api_v1_router` 也仅挂 `wait_for_sync_token`：`src/routing/mod.rs:139-143`。
- `federation_pull_operations` 处理器：`src/routing/federation/federation.rs:1064-1144`。函数体内没有 `verify_federation_origin` / `federation_origin_denied` / `verify_inbound_*_http_signature` / `authenticated_session` 任何调用；只校验 `space_id` 格式并按 `operation_is_visible` 过滤 redaction（1117-1129 行），随后直接返回 operations。
- `federation_space_members` 处理器：`src/routing/federation/federation.rs:1262-1291`，直接读取 `state.realms` 返回某 realm 全部成员 `principal_id`，无任何调用方校验。
- `federation_anchors_pull` 处理器：`src/routing/federation/federation.rs:2319-2341`，对任意 `space_id` 列出全部本地 Anchor，无来源校验。

对照：同文件内的 `federation_transaction`（60-241）与 `federation_push_operations`（252-284）都调用了 `verify_federation_origin`、`federation_origin_denied`、`verify_inbound_*_http_signature`，证明这套准入控制是该子系统的既定基线，三个读端点系遗漏。

**影响**：任何能访问该 HTTP 端点的客户端（含未配置为联邦 peer 的任意网络主体）可：枚举任意 `realm_id` 的成员 DID 列表（隐私/反枚举失效），拉取 realm 的事件操作流与 Anchor finality 信息。`pull-operations` 虽过滤了已 redact 的 operation，但仍暴露未加密元数据/明文 operation 与因果结构，且 `space-members` 直接泄露成员关系。与 spec `realm` 作为“同步/鉴权/联邦边界”的定位（spec_digest §0）相悖：跨域读取应受 `federation_policy` 与 peer denylist 约束。

**建议**：对三个 GET 端点加入与 push/transaction 一致的准入：(a) 要求并校验联邦 HTTP Message Signature（复用 `verify_inbound_federation_http_signature` 的 source/destination/trust-domain 绑定）或本地 `authenticated_session`；(b) 调用 `federation_origin_denied` 与 `enforce_realm_federation_policy`（`closed/quarantine/restricted` 应拒绝）；(c) `space-members` 增加按调用方成员资格的可见性裁剪。

**复验结论**：已重新打开 `mod.rs:33-56`、`federation.rs:1064-1144/1262-1291/2319-2341` 与中间件链 `mod.rs:101-143` 核对，确认这三个处理器路径上无任何认证/来源/denylist 调用，属实。

---

## 问题 2：`federation_anchors_push` 无 HTTP 签名 / denylist 校验即写入本地 Anchor DAG

**严重级别**：P1

**证据**：
- `src/routing/federation/federation.rs:2349-2374+`：处理器仅调用 `verify_federation_origin(&body.origin)`（仅校验 `origin` 是“格式合法的 DID 字符串”，见 `2015-2027` 行实现），随后对每个 anchor 校验 `anchor.derive_id() == anchor.id`（2368-2374）后接受写入。
- 缺失项对比：`federation_push_operations`（`:274`）会调 `verify_inbound_push_http_signature`，`federation_transaction`（`:90`）会调 `verify_inbound_transaction_http_signature`，二者还调 `federation_origin_denied`；而 `federation_anchors_push` 两者皆无。

**影响**：任意网络主体可向本服务推送自构造的 Anchor（只要 `id` 等于其内容哈希——这是内容寻址的天然约束，攻击者完全可自行满足），从而向本地 finality DAG 注入节点、推进/污染 realm frontier 与 state_root 视图。结合问题 1 的 anchors-pull，可形成读写双向的未授权联邦面。`verify_federation_origin` 不做密钥解析或签名验证，无法阻止伪造 `origin`。

**建议**：在写入前要求并验证联邦 HTTP Message Signature（`verify_inbound_federation_http_signature`），并加 `federation_origin_denied` + `enforce_realm_federation_policy(Inbound)`；anchorer 签名（`anchorer_signature`）应按 realm 配置的 anchorer 公钥实际校验，而非仅校验内容寻址 id。

**复验结论**：已核对 `federation.rs:2349-2374` 与 `verify_federation_origin` 实现 `2015-2027`，确认无签名验证、无 denylist，属实。

---

## 问题 3：blob 下载/presign 的 T11 fail-closed 闸门被硬编码绕过（redaction/legal_hold 未生效）

**严重级别**：P2

**证据**：
- `src/routing/interop/blob.rs:588-596` `presign_blob_policy_value()` 把判定输入**写死**：`"legal_hold": false`、`"redacted": false`、`"visibility": null`，仅 `encryption`/`uploaded_by` 来自真实记录。
- 判定函数 `classify_presign_blob_block()`（`:928-955`）正是依据上述字段判断 `LegalHold`/`Redacted`/`ActorPrivate`。由于输入恒为 false/null，这三类闸门**永不触发**，只剩 `E2ee`（依据真实 `encryption`）有效。
- 该函数同时用于直发路径 `blob_get`（`:344`）和 `blob_presign`（`:525`）。
- `BlobRecord`（`src/state.rs` 中定义，blob.rs:221-232 构造处可见字段集）不含 `legal_hold`/`redacted`/`visibility` 字段，因此即便记录被标记 redacted，下载路径也无从感知。

**影响**：spec T11 要求对 legal hold / 已 redact / actor_private 的 blob 在 presign 与直发时 fail-closed；当前实现使这三类保护形同虚设。若上层将某 blob 标记为已 redact 或置于 legal hold，攻击者/普通成员仍可正常下载其内容——属“erasure/redaction 未真正生效”。

**建议**：在 `BlobRecord` 增加 `legal_hold`/`redacted`/`visibility`（或从权威 projection 查询）并在 `presign_blob_policy_value` 用真实值填充；为这三类增加回归测试（当前测试 `:979-1017` 用手构造 JSON，掩盖了生产路径恒 false 的事实）。

**复验结论**：已重新打开 `blob.rs:588-596`、`:928-955`、`:344`、`:525` 核对，确认硬编码值导致三类闸门不可达，属实。

---

## 问题 4：egress SSRF 守卫存在 DNS rebinding TOCTOU（解析 IP 未钉入请求）

**严重级别**：P2

**证据**：
- `src/security.rs:76-133` `validate_url_for_egress_with_resolver`：解析主机名得到一组 IP 并逐个 `validate_resolved_ip`，校验通过后**仅返回 `Ok(())`**，调用方拿到的仍是原始 `Url`（`validate_http_url_for_egress` 返回 `Url`，`:17-30`）。
- 实际请求由 `build_*_egress_http_client`（`:32-74`）构造的 reqwest client 发起，client 在 connect 时**重新做 DNS 解析**，并未使用上一步校验过的 IP；代码未做 `resolve` 钉定（无 `.resolve()`/IP 直连）。
- 调用点示例：OAuth introspection `src/routing/identity/auth.rs:899-925`、federation backfill/pull `src/routing/federation/federation.rs:2085-2095`、webvh probe `src/did_resolver_chain.rs:158-168`——均“先校验 URL，再用普通 client 发请求”。

**影响**：经典 DNS rebinding：攻击者控制的域名在校验时解析为公网 IP（通过），在 client 连接时解析为 `169.254.169.254` / `127.0.0.1` / 内网地址，绕过守卫访问云元数据/内网服务（SSRF）。守卫已正确拦截字面内网 IP 与“校验期返回内网答案”的情况（测试 `:442-476`），但无法防 connect-time 重解析。

**建议**：把校验通过的具体 IP 钉入请求（reqwest `ClientBuilder::resolve`/`resolve_to_addrs`，或自定义 DNS resolver 仅返回已校验 IP），确保“被校验的 IP == 被连接的 IP”；并对每个 egress 调用统一走该路径。

**复验结论**：已核对 `security.rs:17-133`、客户端构造 `:32-74` 及三处调用点，确认校验 IP 未传递到连接阶段，TOCTOU 成立，属实。

---

## 问题 5：blob 直发 presigned 分支跳过可见性检查 + presign 令牌不绑定接收者

**严重级别**：P2

**证据**：
- `src/routing/interop/blob.rs:297-334`：`blob_get` 中 `validate_presign_query` 通过即 `presigned=true`，鉴权失败也允许 `session=None` 继续（`:298-310`）；随后可见性判定 `:320-330` 对 `session=None` 直接令 `denied=false`，即 **presigned 请求完全跳过 `blob_visible_to_session`**。
- presign 令牌签名输入 `presign_signing_input`（`:576-586`）只绑定 `service_did/trust_domain/blob_ref/purpose/expires_at`，**不含接收者 actor/device**；`presign_token`（`:570-574`）据此签发。

**影响**：presign URL 是不记名 bearer URL，任何持有该 URL 的人在 TTL 内（≤300s，`:533`）均可下载，且服务端不再校验 realm 成员资格。一旦 presign URL 经日志/Referer/转发泄露（问题已部分用 `no-referrer`/`no-store` 缓解，`:961-962`），即构成越权读取；签发时虽有成员校验（`:514-523`），但令牌可被任意转交他人使用。

**建议**：(a) presign 令牌签名输入纳入授权接收者标识（actor/device 或一次性 nonce 并服务端记录消费），实现一次性/绑定；(b) 直发 presigned 分支仍应对 blob 的 realm 做最小可见性/策略校验（至少复核 legal_hold/redacted，参见问题 3）。

**复验结论**：已核对 `blob.rs:297-334`、`:570-586`，确认 presigned 分支跳过可见性、令牌不绑定接收者，属实。

---

## 问题 6：debug 构建无条件开放 conformance 端点（含签名/redact 测试面）

**严重级别**：P3

**证据**：
- `src/routing/conformance/mod.rs:60-68` `endpoints_enabled()`：`if cfg!(debug_assertions) { return true; }`——debug 构建**无视** `SOLAND_ENABLE_CONFORMANCE_ENDPOINTS` 一律启用。
- 端点含 `/conformance/sign`（`handlers.rs:127-151`）、`/conformance/redact`、`/conformance/snapshot` 等，且无 `authenticated_session` 校验（路由 `mod.rs:42-53`）。

缓解：`sign` 使用从调用方 `signing_key_ref` 派生的确定性密钥（`handlers.rs:139-151`），**非真实账户/服务密钥**，故不构成真实身份签名 oracle；`chaos/operation` 另有 `development_mode` 二次门（`handlers.rs:534-536`）。

**影响**：若运维误将 debug 构建部署到生产（常见失误），将暴露 conformance 测试面（信息/指纹、redaction 投影逻辑探测）。因签名 oracle 用的是派生密钥，危害有限，故 P3。

**建议**：生产门改为同时要求显式 env（去掉 `cfg!(debug_assertions)` 短路，或在 release 默认关闭、debug 也需 env），并对整个 `/conformance/*` 加 admin 鉴权。

**复验结论**：已核对 `conformance/mod.rs:60-68` 与 `handlers.rs:127-151/534-536`，确认 debug 无条件开放、签名密钥为派生密钥，属实。

---

## 问题 7：密钥/凭据/证明比较使用非常量时间 `==`

**严重级别**：P3

**证据**：全仓 `rg "subtle|constant_time|ct_eq|ConstantTime"` 无任何命中（未引入常量时间比较库）。具体非常量时间比较：
- presign 令牌：`src/routing/interop/blob.rs:567` `token == presign_token(...)`。
- 开发删除证明：`src/routing/identity/key_backup.rs:743` `proof == format!("dev-ssk-delete:v1:{actor_id}:{backup_id}")`。
- 联邦幂等键比较与 cache 命中：`src/routing/federation/federation.rs:132`（`record.content_digest == content_digest`）等多处 digest 直接 `==`。

已有良好实践（对照）：webvh 注册 bearer 用 `sha256_hex(provided) != sha256_hex(expected)` 比较（`src/routing/identity/did.rs:896`），等价常量时间；会话 token 走哈希后作 DB 主键查找，不做明文 `==`（`auth.rs:700-715`）。

**影响**：理论上可经时序侧信道逐字节猜测 presign 令牌 / 删除证明。实际可利用性低：presign 令牌与联邦 digest 是签名/哈希派生（伪造需密钥），dev 删除证明仅 dev-mode 有效；故 P3。

**建议**：对所有“与秘密的相等比较”统一改用 `subtle::ConstantTimeEq`（或先各自 SHA-256 再比较），尤其 presign 令牌与任何 bearer/证明字符串。

**复验结论**：已核对上述行号与 `did.rs:896` 既有安全实现，确认存在非常量时间比较，影响有限，属实。

---

## 问题 8：恢复端点未绑定 `session.actor == principal_id`（权限隔离偏弱）

**严重级别**：P3

**证据**：
- `src/routing/identity/recovery.rs:923-1011` `recovery_policy_put`：取 `session = authenticated_session(...)`（`:931`）但 `principal_id` 来自请求体（`validate_recovery_policy` → `record.principal_id`，`:934`），随后仅对 `record.principal_id` 的 DID 做签名校验（`verify_recovery_auth_signature`，`:935-943`）；**未**比较 `session.actor` 与 `record.principal_id`。`recovery_receipt_put`（`:1023-1043`）同样。
- 对照：恢复会话读/写端点确有隔离（`resolve_recovery_read_principal:154-163`、`recovery_session_create:405-413`、`load_owned_recovery_session:372-379`），说明“principal 隔离”是本模块既定要求，policy/receipt 两个写端点未一致执行。

缓解：写入需 `principal_id` 私钥对 canonical signed_fields 的有效 Ed25519 签名（`:1457-1488`），故非任意伪造；属“认证用户可代他人提交（relay）”而非完全绕过。

**影响**：任一持有效 bearer 的 actor 可代任意 principal 提交其已签名的 recovery policy/receipt（如重放他人此前泄露的已签名文档），与同模块其它端点的“仅本人”隔离不一致；可能影响审计归属与策略单调性边界的清晰性。

**建议**：在 `recovery_policy_put` / `recovery_receipt_put` 增加 `record.principal_id == session.actor` 校验（与 `recovery_session_create:406-413` 一致），保持模块内 principal 隔离一致；如确需 relay 语义应显式记录并限定能力。

**复验结论**：已核对 `recovery.rs:923-943/1023-1043` 与隔离实现 `:154-163/372-379/405-413`，确认两写端点缺少 actor==principal 校验，签名提供兜底，属实，列为 P3。

---

## 附：已核对但判定为“非问题/可接受”的项（避免误报）

- **dev-login 仅 dev-mode**：`auth.rs:178-180` 生产返回 404；OAuth introspection 走 egress 守卫 + 常量时间下限 + jitter（`auth.rs:815-887`，随机数源用 `OsRng`），时序缓解到位。
- **policy_gate fail-closed**：`authz.rs:728-744` policy client 出错时合成 deny；`policy_gate.rs` 在无 policy server 配置时返回 Ok 系按设计（本地 authz 另行生效），非 fail-open。
- **unsafe 块**：全部为启动期 `env::set_var/remove_var`（`main.rs:57`、`config.rs:1073`、`security.rs` 测试、`verified_profiles.rs:298`），有 SAFETY 注释、单线程启动期调用，无内存安全问题。
- **CORS 通配**：仅 dev-mode 默认 `*`（`config.rs:439-443`），且 `*` 分支用 mirror-origin 且不带 credentials（`routing/mod.rs:1318-1327`），生产需显式配置，可接受。
- **egress client 禁用重定向**：`security.rs:39/61` `redirect::Policy::none()`，已防重定向 SSRF 绕过（DNS rebinding 仍是问题 4 的独立缺陷）。
- **key backup 跨 actor 覆盖防护与 KDF floor**：`key_backup.rs:775-788`（跨 actor 拒绝）、`:209-276`（argon2id/pbkdf2 floor 与 degraded reason）、删除需 JWS 所有权证明（`:702-773`），实现稳健。
