# soland 审查报告 07：存在更优方案 / 依赖库 / 技术未使用

> 被审项目：`D:/Works/contrix-dev/soland`
> 协议锚点：`contrix-spec/spec/v1`；SDK 真源：`contrix-rust-sdk/crates/{core,contracts}`
> 本报告聚焦：已有更成熟/安全/高效的库或语言特性却未采用 —— 手写实现、低效数据结构、未用 newtype/type-state、未用现成 canonical-json/jose/mls、异步并发可改进、可复用 SDK 既有能力。

## 审查范围

实际通读 / 检索的路径（相对 `soland/`）：

- ID 生成与类型化：`src/ids.rs`（全文 1-90、430-460）；对照 SDK `contrix_identifiers` 导出的 `RealmId/CircleId/...::generate()/::parse()`
- 持久化查询风格：`src/persistence.rs`（`sql_query` vs Diesel DSL 统计、`QueryableByName`）、`src/schema.rs`
- 加密/签名/canonical：`src/jws_verify.rs`（全文）、`src/anchorer.rs`（头部 1-60、签名段 200-250、540-560）—— 确认是否复用 SDK
- DID 解析的异步桥接：`src/did_resolver_chain.rs:107-134`
- 内存并发结构：`src/state.rs:836-990`（`Arc<Mutex<…>>` 选型）
- HTTP egress：`src/security.rs:40-130`

复验命令：

```
grep -n 'pub fn generate' src/ids.rs
grep -rn ': RealmId\|: &RealmId\|: CircleId\|: SpaceId' src --include='*.rs' | grep -v test | wc -l   # 11
grep -rn 'realm_id: &str\|realm_id: String\|space_id: &str\|circle_id: &str' src | grep -v test | wc -l  # 276
grep -c 'sql_query' src/persistence.rs       # 144
grep -rn 'crate::schema\|::dsl::\|accounts::table' src | grep -v test   # 0 命中
grep -n 'std::thread::spawn\|block_on' src/did_resolver_chain.rs
```

未覆盖说明：优先覆盖了与 SDK 能力直接重叠、以及类型安全/性能影响最大的点。各 handler 内部的局部算法（如分页、查询拼装细节）未逐一评估其复杂度。MLS / 联邦的密码学细节以"是否复用 SDK"为切入，未做协议正确性深查（属其他报告维度）。

## 结论摘要

soland 在**密码学层做得很好**：JWS 验证、canonical bytes、anchor 签名都正确地委托给了 `contrix_sdk::jws` / `contrix_sdk::anchor`，没有手写 crypto（见问题"附"）。主要可改进点集中在**类型系统未充分利用**：SDK 提供了一整套 typed ID newtype（`RealmId`/`CircleId`/…，带校验的 `generate()`/`parse()`），soland 却自建返回 `String` 的 `generate_*_id()` 并在 276 处函数签名里以 `&str`/`String` 传递 ID，几乎放弃了类型安全。其次是**Diesel 类型化 DSL 完全弃用**（144 处裸 SQL + 死 `schema.rs`），以及 **DID 解析每次新建线程+运行时**的反模式。下列 4 条按收益排列。

---

## 问题 1：放弃 SDK 的 typed-ID newtype，全程用 `String`/`&str` 传递标识符

### 严重级别
P1

### 证据
- SDK 真源 `contrix-rust-sdk/crates/core/src/model/` 通过 `contrix_identifiers` 导出强类型 ID：`RealmId/SpaceId/CircleId/FlowId/MessageId/...`，带 `::generate()` 与 `::parse()`（spec_digest §5.1）。soland 测试自身就用过：`src/ids.rs:448` `RealmId::generate()`、`:431` `RealmId::parse(&wire)`、`:440-442` 用 `RealmId::parse` 做负例校验，证明该能力可用且 soland 已依赖它。
- 但生产代码里 soland 自建一套**返回裸 `String`** 的生成器：`src/ids.rs:22` `pub fn generate(kind: &str) -> String { format!("cx:{kind}:{}", Uuid::now_v7()) }`，并派生 `generate_realm_id`(30)/`generate_circle_id`(49)/`generate_space_id`(26) 等 14 个全部返回 `String`。
- ID 在函数签名里几乎全是无类型字符串：`grep` 统计 `realm_id: &str|realm_id: String|space_id: &str|circle_id: &str` 等在非测试代码命中 **276 处**；而真正用 typed ID（`: RealmId`/`: CircleId`/`: SpaceId`）的签名仅 **11 处**。

### 影响
- **类型安全几乎为零**：`realm_id`/`circle_id`/`space_id` 都是 `&str`，编译器无法阻止把 circle id 传进期望 realm id 的参数（在边界倒置后的模型里，Realm 与 Circle 的混淆正是高危区）。
- 校验分散：`src/ids.rs` 另写了 `parse_typed_uuid` 等手工解析（86 行起），与 SDK `*::parse()` 的校验逻辑重复，且重复实现易与 spec 编码规则漂移。
- 自建 `generate()` 用 `Uuid::now_v7()` 直接 `format!`，绕过 SDK 可能携带的不变量（前缀校验、UUIDv7 pattern 校验）。

### 建议
- 用 SDK 的 typed ID 替换 soland 自建生成器：`generate_realm_id()` → `RealmId::generate()`，并让生成器返回 typed ID 而非 `String`。
- 渐进迁移函数签名：先在新代码与跨边界 API 处用 `RealmId`/`CircleId`/`SpaceId`，把"Realm vs Circle vs Space"混淆推到编译期。`&str` 仅在最外层 wire 解析处出现，进入业务层即转 typed。
- 删除 `src/ids.rs` 中与 SDK 重复的 `parse_typed_uuid` 等，统一走 `*::parse()`。

### 复验结论
已重新打开 `src/ids.rs:22-84`、`:431/:440/:448` 与复跑两组 grep（276 vs 11）核对：自建 String 生成器、SDK 能力可用、压倒性的 `&str` 传参均属实。

---

## 问题 2：弃用 Diesel 类型化 DSL，全量裸 SQL（`sql_query` + `QueryableByName`），且生成的 `schema.rs` 成死代码

### 严重级别
P2

### 证据
- 依赖已启用 Diesel 全套（`Cargo.toml`：`diesel` features `postgres,r2d2,serde_json,chrono,uuid` + `diesel-async`），且 `src/schema.rs` 有 29 张 `diesel::table!` 定义、`src/lib.rs:27` `pub mod schema;`。
- 但 `src/persistence.rs` 用 `sql_query`（裸 SQL）**144 处**、`QueryableByName`（裸结果映射）**44 处**；类型化 DSL（`::table`/`insert_into`/`.filter(`）仅 23 处，且经核对均未引用 `crate::schema` 的表模块。
- `crate::schema` / `accounts::table` / `::dsl::` 在非测试代码**零引用**（见报告 04 问题 4）。

### 影响
- 放弃了 Diesel 最大的卖点 —— **编译期 SQL/类型校验**。裸 SQL 的列名拼写、类型不匹配只能在运行时（甚至生产）暴露。
- `schema.rs` 290+ 行成为零收益的维护负担，且无机制保证它与 `migrations/` 一致。
- `QueryableByName` 手工绑定每个 record 的列，样板代码量大且与 SQL 字符串两处都要改。

### 建议
- 决策一条路线：
  - **若坚持裸 SQL**（团队偏好手写 SQL、查询复杂）：删除 `schema.rs` 与 `lib.rs:27`，并把裸 SQL 集中到 `persistence/sql.rs` 常量 + 加 `cargo test` 级别的 schema 一致性校验（如启动时对关键表做一次 `information_schema` 比对）。
  - **若想要编译期安全**：逐步把高频读写迁到 Diesel DSL（`schema.rs` 即可复活其价值），保留少数确需手写的复杂查询为 `sql_query`。
- 无论哪条，至少加 `diesel print-schema` 与 `migrations/` 的 CI 漂移检查。

### 复验结论
已复跑 `grep -c 'sql_query' src/persistence.rs`（144）、DSL 计数与 `crate::schema` 零引用核对，并打开 `src/schema.rs:1-20`/`src/lib.rs:27`。结论属实。

---

## 问题 3：本地 DID 解析为适配 SDK 的同步 `DidResolver` trait，每次都新建 OS 线程 + 新建 tokio 运行时

### 严重级别
P2

### 证据
- `src/did_resolver_chain.rs:107-126` `blocking_webvh_document_lookup`：当已在 tokio 运行时内（`Handle::try_current().is_ok()`）时，**为每一次本地 DID 文档查询** `std::thread::spawn(run_lookup).join()`，而 `run_lookup`（112-118）内部 `tokio::runtime::Builder::new_current_thread().build()` 再 `runtime.block_on(...)` 去 `await` 一个异步的 `persistence.webvh().get_document()`。
- 触发点是 `impl DidResolver for LocalIdentityResolver`（128 起）的 `supports`/`resolve_did` —— SDK 的 `DidResolver` 是**同步 trait**，于是异步持久化只能用"新线程 + 新运行时 + block_on"硬桥接。

### 影响
- **每次 DID 解析一次 thread spawn + runtime 构建 + join**：线程创建与单线程运行时构建都是非平凡开销；DID 解析在 JWS 验证、联邦、身份校验等热路径上被频繁调用，吞吐与尾延迟受损。
- `block_on` 在请求线程上同步阻塞，挤占 tokio worker 行为虽被 spawn 隔离，但 join 仍阻塞调用栈。
- 错误信息被压成 `String`（`map_err(|e| e.to_string())`），丢失结构化错误。

### 建议
- 优先方案：为本地解析准备**同步可读的快照缓存**（启动/变更时把 webvh 文档读入 `Arc<RwLock<HashMap<Did, DidDocument>>>`），`resolve_did` 直接查内存，彻底消除每次 block_on。
- 次选：推动 SDK 提供 `AsyncDidResolver`（或让 soland 维护一个独立的解析缓存层），把异步性沿调用链上移，而非在叶子处反复造运行时。
- 若必须保留 block_on 兜底，至少**复用一个共享的运行时句柄**，不要每次 `Builder::new_current_thread().build()`。

### 复验结论
已重新打开 `src/did_resolver_chain.rs:107-134` 核对：每次查询 spawn 线程 + 新建 current-thread runtime + block_on 属实。

---

## 问题 4：进程内热状态用 `std::sync::Mutex` 而非读写锁 / 无锁结构

### 严重级别
P3

### 证据
- `src/state.rs:3` `use std::sync::{Arc, Mutex};`，`AppState`（836）里约 20 个共享状态全部是 `Arc<Mutex<…>>`：`projection`(842)、`realms`(844)、`consent_cells`(889)、`organizations`(913)、`did_resolver`(924) 等（行号见报告 04 问题 3）。这些是**读多写少**的投影/目录/解析器缓存。
- `projection` 被 76 处读写（`grep -rn 'projection.lock()'` 等），其中绝大多数是只读快照（如 `src/routing/events/event_log.rs:1196` `if let Ok(proj) = state.projection.lock()`）。

### 影响
- `std::sync::Mutex` 对读多写少的投影是**串行化读**：高并发查询互相排队，吞吐受限。
- 在异步 server 里持有 `std::Mutex` guard 跨 `.await` 是已知陷阱（详见报告 12 的并发条目）。

### 建议
- 读多写少者改用 `parking_lot::RwLock`（无毒化、更快、API 更顺手）或 `tokio::sync::RwLock`（需跨 await 时）。`parking_lot` 还能消除 `lock().unwrap()`/`if let Ok(...)` 的毒化分支（见报告 12）。
- 进一步：把目录/解析器缓存换成 `arc-swap`（项目已依赖 `arc-swap`，目前只用于 anchorer 签名 key 热替换）做无锁读路径。
- 真相级数据应下沉 `PersistenceStore`（见报告 04 问题 3），从根上减少进程内共享可变状态。

### 复验结论
已重新打开 `src/state.rs:3`、`:842-924` 与抽查 `src/routing/events/event_log.rs:1196` 核对：`std::sync::Mutex` 选型与只读热路径属实。`arc-swap` 已在 `Cargo.toml` 依赖中（注释说明仅用于签名 key 热替换）。

---

## 附：已正确复用 SDK / 现成库，无需改动的方面

- **JWS / JOSE**：`src/jws_verify.rs:1-26` 明确是 `contrix_sdk::jws` 的薄包装，RFC 7515 detached 形状、Ed25519 验证、DID 解析、replay-window 全在 SDK，soland 不手写 crypto。pure helper（`verify_replay_window*`、`physical_millis_from_hlc`）直接 re-export，避免重复实现。
- **Canonical JSON / Anchor 签名**：`src/anchorer.rs:25-26`/`:241-247` 调 `Anchor::canonical_bytes_for_id()` 与 `contrix_sdk::jws::sign_jws_ed25519`，canonical Merkle `state_root` 也走 SDK，未自造 canonical 序列化。
- **Ed25519 / base58**：用成熟的 `ed25519-dalek` + `bs58`，未手写椭圆曲线或 multibase 解码。
- **agent audit binding 签名**：`src/routing/events/agent_bridge.rs:357` 复用 `contrix_sdk::agent_binding::sign_ed25519_audit_binding`（其默认 seed 的安全问题见报告 12）。

这些是正面范例：密码学与 wire-canonical 一律下沉 SDK，符合"多 repo 共享一份 wire-compatible 实现"的目标。
