# Agent 子系统设计(soland)

> 勘察快照,截至 d28714b。本文「现状基线」描述以该 commit 为准,后续实现演进可能使其失真。

支撑 CKP-0016(agent 参与策略)落地所需、当前缺失或 stub 的四个 soland 子系统的完整设计。真源协议见 `cokret-spec/spec/v1/proposals/0016-agent-participation-policy.md` 与 CKP-0008/0009。

设计原则:复用现有事件管线与 reducer/cell 投影模型,不另起并行栈;字段顺序与 spec 一致;直接改现有 SQL;无兼容层。

现状基线(已勘察):
- 事件提交:`routing/events/event_log.rs::submit_event_value` → `store.put(CanonicalEventRecord)` → `routing/events/projection.rs::project_accepted_operations_from_device` → `reducer.rs::ProjectionState::apply` 经 `APPLY_REGISTRY`(`kind → apply_*`)分发。
- reducer 范式:`apply_circle_update`(tighten-only floor + 字段 patch)、`apply_realm_policy_components`(floor ratchet + cell write `ck.component.realm.policy_components.v1`)、`apply_realm_policy_server`(cell + side-band BTreeMap 缓存)。
- capability grant:存于 cell `ck:cell:ck.component.capability.grant.v1:<capability_id>`,authz 经 `capability_grant_cells` / `grants_for_realm` 读取;`ck.capability.derived` 已注册 reducer(`apply_capability_derived_dispatch`)——capability 事件→cell 的先例。
- 消息:`apply_message` 仅写 `MessageState`,无 fanout。
- 通知:**无** NotificationStore / fanout / mention→notification。mention 仅在 `wire_validators/mention.rs` + `routing/events/operations.rs::validate_mentions` 做语法校验。
- session:`routing/identity/auth.rs::exchange_session_grant` 返回 SDK `SessionLoginOutcome`,grant 验证委托 coauth;无 `agent_key_proof`、无 `scope_details`。

---

## S0(共享底座)— 服务端内部 durable event 发射器

S1、S2 都需要服务端"主动"写入 durable event(controller 调 `participation.set` 时由服务端编排出 `ck.capability.grant`)。当前 `submit_event_value` 是 client-driven(需 actor proof + actor_seq 单调)。新增一个 server-originated 旁路:

```rust
// routing/events/server_emit.rs (新文件)
/// 服务端编排发射一条 durable event:构造 envelope(service_did 作为 actor / proof),
/// 持久化到 event store,并投影。复用 submit_event_value 的 store.put + project 两步,
/// 但跳过 client actor_seq 单调与 actor proof 校验(由服务端信任边界保证)。
pub(crate) async fn emit_server_event(
    state: &AppState,
    realm_id: &str,
    kind: &str,
    payload: Value,
) -> Result<String /*event_id*/, AppError>;
```

要点:
- envelope `actor_id = state.config.service_did`,`actor_kind="service"`,`event_id = ids::generate("event")`,`created_at = now()`,proof 为 service 签名(复用 notary/signer 已有 service key)。
- 写入走 `state.persistence.events().put(CanonicalEventRecord{..})`,再 `projection::project_accepted_operations_from_device(state, service_did, service_device, &[operation])`。
- 幂等:server-emit 的 event_id 由内容确定性派生(对 grant:`hash(subject, scope_key, actions)`)以避免重复编排产生孤儿。
- 该 helper 是 S1/S2 唯一被允许绕过 client 提交校验的入口;其它路径不得直接 `store.put`。

实现位置:`routing/events/mod.rs` 暴露 `pub(crate) mod server_emit;`。

---

## S1 — Capability grant 物化(`ck.capability.grant` / `ck.capability.revoke`)

**目标**:`participation.set` 中 `reply`/`act_on_behalf` effective 为真 → 发射 `ck.capability.grant`(agent 为 subject,scope 为 resource);为假 → `ck.capability.revoke`。读侧(authz `grants_for_realm` 读 grant cell)已存在,只补写侧。

### 事件与 reducer
- `kinds.rs`:新增 `CK_CAPABILITY_GRANT = "ck.capability.grant"`、`CK_CAPABILITY_REVOKE = "ck.capability.revoke"`(若 event-kind-registry 已注册则对齐命名)。
- `reducer.rs`:`APPLY_REGISTRY` 注册 `apply_capability_grant_dispatch` / `apply_capability_revoke_dispatch`,镜像 `apply_capability_derived` 的 cell 写法。

```rust
fn apply_capability_grant(&mut self, op: &Operation) -> ProjectionEffect {
    // payload: { capability_id, issuer, subject, actions[], resources[], constraints[], expires_at }
    let cap_id = op.payload.get("capability_id").and_then(Value::as_str)...; // reject if missing
    let cell = CellRef::new(format!("ck:cell:ck.component.capability.grant.v1:{cap_id}"))?;
    // 校验:issuer 有 ck.capability.grant 授权(已有 authz 引擎);subject/resources 格式;
    //       resources 的 realm_id == op.realm_id。
    self.cells.insert(cell, CellState::Value(grant_value));      // 与现有 grant 读侧同 schema
    ProjectionEffect::CapabilityGrantProjected { capability_id, action: "granted" }
}
fn apply_capability_revoke(&mut self, op: &Operation) -> ProjectionEffect {
    // payload: { capability_id }。把 grant cell 的 value 标记 revoked=true(grant_snapshot_from_value 已读该字段)。
}
```

### participation.set 编排(替换当前 TODO)
`routing/identity/agents.rs::set_agent_participation` 在落库后:
1. 由 effective(已算)推导目标 grant:
   - `reply=true` → actions `["ck.message.create","ck.reaction.add"]`,resource selector = scope(realm/circle/strand,复用 `cokret_sdk::authz::ResourceSelector`)。
   - `act_on_behalf=true` → 追加 CKP-0008 §4.10 act-on-behalf grant(constraints:`approval_required`/`controller_approval_required`)。
2. capability_id 确定性派生:`ck:capability:` + `hash(agent_principal_id, scope_key, "reply"|"aob")` → 同 scope 同 bit 复用一条 grant,幂等。
3. effective bit=true 且 grant 不存在/已 revoked → `emit_server_event(.., CK_CAPABILITY_GRANT, payload)`;bit=false 且 grant active → `emit_server_event(.., CK_CAPABILITY_REVOKE, {capability_id})`。
4. 与 `put_selection` 同一 handler 内顺序执行;任一步失败返回 `AppError::internal`,不留半物化(grant 发射放在 selection 落库之后,失败时记录 audit 供重试)。

`grant.attach`/`grant.detach`/`agent.deactivate` 的同类 TODO 用同一 `emit_server_event` 收敛。

### 验收
- `participation.set reply=true` 后 `grants_for_realm` 能查到该 agent 的 `ck.message.create` grant;`reply=false` 后该 grant `revoked=true`。
- agent 以自身 actor 提交 `ck.message.create` 到该 scope,authz 通过;无 grant 时 fail closed。

---

## S2 — Agent participation ceiling 写入 reducer

**目标**:把 `agent_participation` ceiling 写进 reducer 与 `agent_participation_ceiling` 表(participation.set 的 `resolve_effective_ceiling` 读侧已就绪)。

### Realm ceiling(`ck.realm.policy_components` 的 `agent_participation` 组件)
扩展 `apply_realm_policy_components`(reducer.rs):
- payload 含 `agent_participation.native_agent.{reply,accept_third_party_mention,act_on_behalf}` 时:
  - tighten-only 校验:与 deployment 默认 ceiling 比较(`AgentParticipation::ALL` 为 dev 默认;部署可经 sovereign profile 收紧),用 `cokret_sdk::models::validate_agent_participation_tightens(parent, child)`;违反 → `ProjectionEffect::Rejected { reason: "agent_participation_ceiling_widen" }`(已注册 error code)。
  - 写 cell `ck:cell:ck.component.realm.policy_components.v1:<realm_id>`(已存在,合并字段)。
  - **投影到 ceiling 表**:`ProjectionEffect` 触发把 `{scope_kind:"realm", scope_key:"realm:<uuid>", realm_id, bits}` UPSERT 进 `agent_participation_ceiling`(经 S2 的 ceiling store 写方法,见下)。

### Circle / Strand ceiling
- `apply_circle_update` / `apply_strand_update`:patch 含 `agent_participation` 时,读父级 ceiling(Circle 的父=Realm ceiling;Strand 的父=其 `scope_circle_id` 指向的 Circle ceiling,否则 Realm)→ `validate_agent_participation_tightens(parent, child)` → 写对象字段 + UPSERT ceiling 表行(`scope_key = circle:<r>:<c>` / `strand:<r>:<f>`)。
- 复用现有 tighten-only 框架(与 `content_encryption_floor` 同处校验)。

### ceiling store 写方法
`persistence.rs::AgentParticipationStore` 增 `put_ceiling(record: Value)`(UPSERT `agent_participation_ceiling`,key=scope_key);内存实现写 `ceilings` Vec(去重 scope_key);Pg 实现 UPSERT。reducer 投影阶段调用(reducer 是同步纯函数 → 经 `ProjectionEffect::AgentParticipationCeilingProjected` 在 `project_accepted_operations_from_device` 的 effect 处理段异步落库,与现有 effect→persistence 落库范式一致)。

### 验收
- realm admin 写 `policy_components{agent_participation.native_agent.reply=true, accept_third_party_mention=false}`;controller 对某 strand `participation.set accept_third_party_mention=true` → `agent_participation_exceeds_ceiling` 被拒。
- Circle ceiling 试图放宽父 Realm → `agent_participation_ceiling_widen` 被拒。

---

## S3 — Notification fanout dispatcher(从零)

**目标**:消息创建时派生 per-recipient notification,应用既有覆盖规则 + **CKP-0016 §9.4.5 第三方 mention gate**,并推送给 floria。这是最大的新子系统;分阶段。

### 数据模型(直接建表)
新迁移列 / 表(改现有 `migrations` 下相关 up.sql;notification 属新表):
```sql
CREATE TABLE notification (
    notification_id   TEXT PRIMARY KEY,          -- ck:notification:<uuid>
    recipient_id      TEXT NOT NULL,             -- actor DID(可为 agent principal)
    realm_id          TEXT NOT NULL,
    source_event_id   TEXT NOT NULL,
    notification_type TEXT NOT NULL,             -- mention | reply | assignment | reaction | watch
    reasons           JSONB NOT NULL DEFAULT '[]'::jsonb,  -- 合并的 reason set
    preview           JSONB,                     -- 按 history visibility 裁剪后的预览
    created_at        TIMESTAMPTZ NOT NULL,
    read_at           TIMESTAMPTZ
);
CREATE INDEX notification_recipient_idx ON notification(recipient_id, created_at DESC);
CREATE INDEX notification_source_idx ON notification(source_event_id);
```
`PushRuleStore` 补 SQL backing(当前仅内存)。新增 `NotificationStore`(trait + 内存 + Pg),接入 `PersistenceStore`(范式同 S 已建的 `AgentParticipationStore`)。

### Dispatcher
新文件 `routing/events/notify.rs`:
```rust
/// 在 MessageCreated 投影 effect 处理后调用。纯派生 + 落库 + 入队,不阻塞提交主路径
/// (best-effort,失败记 audit + metric,不回滚消息)。
pub(crate) async fn dispatch_message_notifications(
    state: &AppState,
    msg: &MessageState,           // 来自 ProjectionEffect::MessageCreated
) -> ();
```
流程:
1. **解析 target**:从 `msg.content.mentions[]` 提取 `subject_id`(direct)与 `audience_mention`(broadcast);从 Strand watch cell 提取 watcher(`ck.strand.watch.set` 已有投影)。
2. **逐 recipient gate**(顺序与 spec §9.4 覆盖序一致):
   - 去重:同 `(actor, source_event_id, type=mention)` 最多一条。
   - 发送者自我 mention 默认不通知。
   - `level=muted` / 个人 blocklist / DND / `dont_notify` push rule 覆盖。
   - **agent 第三方 mention gate(CKP-0016 §9.4.5)**:若 recipient 是 native personal agent(`actor_kind="agent"` 或 `agent_principal` 表命中)且 mention 作者 ≠ 该 agent 的 controller(经 `ck.identity.accountability_grant` 解析)且 effective `accept_third_party_mention=false`(读 `agent_participation` selection ∩ `agent_participation_ceiling`,即复用 `resolve_effective_ceiling` + selection)→ **跳过该 recipient**,不写 notification、不入队。
3. **落库**:`NotificationStore::put`(合并 reason set;reply/assignment/reaction/watch 与 mention 命中同 recipient 时合并为单行)。
4. **入队 push**:对有 push device 的 recipient,构造 frame 调用既有 `routing/interop/push_outbound`(floria),受 `max_recipients` / rate-limit / review gate(audience mention)约束;不得先推后撤。

### 接入点
`routing/events/projection.rs` 处理 `ProjectionEffect::MessageCreated`(及 revise 的新增 mention)处,`spawn` 调 `dispatch_message_notifications`(或推入轻量队列 worker)。同一处也覆盖 `ck.message.revise` 仅对"新增 mention"派生(spec §9.4)。

### 读取 API
`GET /_cokret/self/notifications`(新 operation,后续补)读 `NotificationStore` 返回 recipient 的 inbox;agent runtime 经此 + `ck.self.events.stream.subscribe` 投影获得被允许的 mention。

### 验收
- alice @bob(普通)→ bob 收到 notification + push。
- carol @alice 的 agent,agent 在该 scope `accept_third_party_mention=false` → agent **无** notification、无 subscribe 投影;`=true` → 有。
- controller alice @自己的 agent → 不受 gate(始终投递)。

---

## S4 — Agent session grant `scope_details.participation` overlay

**目标**:agent runtime 换 session 时拿到 resolved 参与契约。当前 `exchange_session_grant` 返回 SDK `SessionLoginOutcome`,无 scope_details、无 agent_key_proof 分支。

### proof_kind 分支
`SessionGrantExchangeRequestBody` 增 `proof_kind`(默认 human;`agent_key_proof` 时走 agent 分支)与 `agent_scope_request{realm_ids[], strand_ids[], track_names[]}`(`ck.profile.agent_auth.v1` overlay,见 CKP-0008 §4.6)。`exchange_session_grant`:
- `agent_key_proof`:校验 key 被 active 未撤销 `ck.agent.key.authorize` 授权 + challenge/audience/digest/nonce/expiry binding(CKP-0008 §4.6 校验链),不走 coauth human 分支;TTL ≤ 15min。
- 返回类型扩展:新增 `AgentSessionGrantOutcome`(或给 `SessionLoginOutcome` 加可选 `scope_details`),含 `granted_scope[]` 与:

```jsonc
"scope_details": {
  "realm_ids": [...], "strand_ids": [...],
  "participation": [ { "participation_scope": {...}, "reply": true,
                      "accept_third_party_mention": false, "act_on_behalf": false } ]
}
```

### participation 解析
对 `agent_scope_request` 覆盖的每个 scope,复用 `agents.rs::resolve_effective_ceiling` + `AgentParticipationStore::list_selections`,算 effective = ceiling ∩ selection,填入 `scope_details.participation[]`(即把 `participation.get` 的解析逻辑抽成共享 fn,session 与 get 端点共用)。

### 防御纵深(已在 spec §7.3)
runtime 副本仅为主动遵守;硬边界仍是 S1 的 grant 校验(reply/aob)+ S3 的 dispatcher gate(mention)。session overlay 不是安全边界。

### 验收
- agent 以 `agent_key_proof` 换 session,响应 `scope_details.participation` 与 `participation.get` 一致;human 分支不受影响。

---

## 实施顺序与并行

```
S0(server_emit) ──► S1(grant 物化)         ┐
S2(ceiling reducer) ── 独立,依赖 S0 的 effect 落库范式 ─┤── 可与 S1 并行
S4(session overlay)── 依赖 participation 解析共享 fn(已存在) ── 独立可并行
S3(notification dispatcher)── 最大,独立子系统;mention gate 依赖 participation 读侧(已就绪)
```

- S1 + S2 + S4 较有界,优先;各自加 reducer/handler 单测 + soland 集成测试。
- S3 分两步:先 NotificationStore + mention 派生 + agent gate(本地可测),再 floria 推送联调。
- 每个子系统落地后回填 `_agents_todos.md` 对应项与 commit hash;cotest 真实联调在 S1–S4 就绪后统一跑。

## 与 spec 的关系
本设计是 soland 实现侧落点,不改协议语义;CKP-0016 与已 merge 的 normative 文本(capabilities §5.4、strand-and-message §9.4.5、realm-and-space §2、circle 字段表、private-objects §4.1)是真源。若实现中发现 spec 不完善,先改 spec 再改码。
