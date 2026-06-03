# soland 审查报告 04：结构建议调整

> 被审项目：`D:/Works/contrix-dev/soland`（Contrix v1 参考主服务端，~12.7 万行）
> 协议锚点：`contrix-spec/spec/v1`；SDK 真源：`contrix-rust-sdk/crates/{core,contracts}`
> 本报告聚焦工程结构维度：模块/文件划分、循环依赖、过大文件/函数、职责混杂、可见性、错误类型组织、目录布局。

## 审查范围

实际通读 / 检索的路径（均为相对 `soland/` 的路径）：

- 顶层布局与各文件行数：`src/*.rs`、`src/reducer/`、`src/routing/**`、`src/authz/`、`src/wire_validators/`、`src/bin/`
- 重点通读：`src/lib.rs`、`src/reducer.rs`（头部模块文档 + `apply` 分派 3619-3727）、`src/persistence.rs`（trait 与两套 impl 定义 1001/1044/1138/3809/3879）、`src/state.rs`（`AppState` 836-990 + 其后约 50 个 record struct 1002-1700）、`src/error.rs`（`reasons` 模块 1-500、`AppError` 509-624）、`src/routing/mod.rs`（1-40 模块声明 + 可见性）、`src/schema.rs`（Diesel `table!` 1-20）
- 跨模块依赖：`state.rs` ↔ `persistence.rs` ↔ `reducer.rs` 的 `use crate::*` 关系

复验命令（PowerShell / bash 均可）：

```
find src -name '*.rs' | xargs wc -l | sort -rn | head
grep -n 'pub trait PersistenceStore\|pub struct MemoryPersistenceStore\|pub struct PgPersistenceStore\|impl PersistenceStore for' src/persistence.rs
grep -n 'pub struct AppState\|pub struct .*Record' src/state.rs
grep -rn 'use crate::state\|use crate::persistence\|use crate::reducer' src/state.rs src/persistence.rs
grep -c '#\[cfg(test)\]' src/reducer.rs src/persistence.rs   # 各为 1，确认非测试占绝大多数
```

未覆盖 / 优先级说明：优先覆盖了体量最大、耦合最深的核心文件（reducer / persistence / state / error / routing 框架）与目录布局。`routing/**` 下各 handler 的内部结构、`reducer/mls.rs`/`realm_links.rs` 等子模块仅做规模与边界审视，未逐行通读。本报告**不**穷尽每个过大函数，只列出最具代表性的结构问题。

## 结论摘要

soland 整体目录分层是清晰的（`routing/` 按领域切子目录、`reducer/` 拆子模块、错误码集中在 `error.rs`、可见性大量使用 `pub(crate)`），工程基线良好。但存在几处**严重的"巨石文件"与职责混杂**：单文件 `reducer.rs`（10560 行）、`persistence.rs`（9374 行）、`state.rs`（2507 行且把 DTO record 与 `AppState` god-object 混在一起）。同时存在一处明确的**死模块**（`schema.rs` 整个 Diesel schema 未被任何代码引用），以及 `state.rs ↔ persistence.rs` 的**层次倒置耦合**。下列 6 条按严重度排列。

---

## 问题 1：`reducer.rs` 与 `persistence.rs` 是 8000+ 行的巨石文件，且各自承载多职责

### 严重级别
P1

### 证据
- `src/reducer.rs`：总 10560 行，首个 `#[cfg(test)]` 在 8225 行 —— 即**非测试代码约 8200 行**集中在一个文件 / 一个模块里。文件内含 300+ 个 `fn`（`grep -c 'fn ' src/reducer.rs` = 301），从 ID/payload 解析（`message_event_id_from_ref` 853、`poll_options_from_content` 959）、各对象的 `apply_*` 分派（1399-1560 一长串 `apply_*_dispatch`）到 `ProjectionState::apply`（3619）全部塞在同一文件。
- `src/persistence.rs`：总 9374 行，首个 `#[cfg(test)]` 在 8295 行 —— 非测试约 8300 行。单文件内定义了 `pub trait PersistenceStore`（1001）、**两套完整实现** `MemoryPersistenceStore`（1044/1138）与 `PgPersistenceStore`（3809/3879），外加 30+ 个 `MemoryXxxStore` 子结构（见 1044-1083 的字段列表）。`grep -c 'fn '` = 732。

### 影响
- 单文件编译单元过大，增量编译慢；任何小改动触发整文件重编。
- 评审 / merge 冲突高发；新人定位某一对象的 reducer 逻辑要在万行内滚动。
- `Memory` 与 `Pg` 两套实现并排，容易出现"只改了一套"的行为漂移（同一 trait 两套 8000 行实现，极难肉眼对齐）。

### 建议
- 按 contrix 对象族拆分 reducer：`reducer/message.rs`、`reducer/relation.rs`、`reducer/membership.rs`、`reducer/realm.rs`、`reducer/space.rs`、`reducer/poll.rs`……（`reducer/` 目录已存在，只需把 `reducer.rs` 中按 `apply_*_dispatch` 已经天然分组的逻辑迁入）。`ProjectionState` 结构定义与 `apply` 总分派留在 `reducer/mod.rs`。
- 把 `persistence.rs` 拆为 `persistence/mod.rs`（trait + 错误类型）、`persistence/memory/`（按子 store 一文件一域，结构已天然存在 `MemoryAccountStore` 等）、`persistence/postgres/`（按域拆 `PgPersistenceStore` 的 impl 块）。
- 测试随各域代码就近落入对应子模块的 `#[cfg(test)] mod tests`。

### 复验结论
已重新打开 `src/reducer.rs:1-80`、`:3619`、`src/persistence.rs:1001`/`:1044`/`:3809` 核对：行数、trait/双实现位置、`#[cfg(test)]` 起始行均属实。

---

## 问题 2：`state.rs` 把 DB record（DTO）与 `AppState` god-object 混在同一模块，造成层次倒置耦合

### 严重级别
P1

### 证据
- `src/state.rs:836` `pub struct AppState`，紧随其后（约 `1002-1700`）定义了 ~50 个持久化 record：`SessionRecord`(1002)、`AccountRecord`(1025)、`RecoveryPolicyRecord`(1052)、`MessageRecord`(1265)、`CanonicalEventRecord`(1276)、`FederationOutboxRecord`(1352)、`PushRuleRecord`(1421)、`WebrtcSessionRecord`(1455)、`OrganizationRecord`(1533)…… 直到 `RetentionTombstoneRecord`(1651)。
- `src/persistence.rs:23` `use crate::state::{AccountDataRecord, AccountRecord, ... WebvhLogRecord};` —— 持久化层反向依赖"应用状态"模块来取数据传输对象。
- 同时 `src/state.rs:20-21` `use crate::persistence::{MemoryPersistenceStore, PersistenceStore, PgPersistenceStore};` 与 `use crate::reducer::ProjectionState;`。

即 `state.rs` 依赖 `persistence`/`reducer`，而 `persistence.rs` 又回头依赖 `state` 的 record 类型 —— 形成 `state ↔ persistence` 的双向（循环含义上的）耦合。DTO 本应是被两端共享的底层，却寄生在最上层的 `AppState` 模块里。

### 影响
- 持久化层与"应用顶层 state"互相 `use`，破坏分层（理想方向：domain/record ← persistence ← state/runtime）。
- 任何 record 字段调整都牵动 `AppState` 所在模块重编；DTO 复用受限（例如 federation / sync handler 只想引 record 也得拉进整个 state 模块）。

### 建议
- 新建 `src/records/`（或 `src/model/`）模块，把所有 `*Record` DTO 迁出 `state.rs`。`persistence.rs` 改为 `use crate::records::*`，`state.rs` 同样从 `records` 引入。
- `AppState` 模块只保留运行时句柄（`Arc<dyn PersistenceStore>`、各 `Arc<Mutex<…>>`、配置、广播 channel）。

### 复验结论
已重新打开 `src/state.rs:20-21`、`:836`、`:1002`/`:1265`/`:1651` 与 `src/persistence.rs:23` 核对：双向 `use` 与 record 定义位置属实。

---

## 问题 3：`AppState` 是承载 ~38 个 `pub` 字段、约 20 个 `Arc<Mutex<…>>` 影子状态的 god-object

### 严重级别
P1

### 证据
- `src/state.rs:836` `pub struct AppState`，`grep` 统计字段约 38 个 `pub`。其中既有 `persistence: Arc<dyn PersistenceStore>`(839)、`projection: Arc<Mutex<ProjectionState>>`(842)，又并列 ~20 个独立的内存影子表：`realms`(844)、`handle_releases`(851)、`account_lifecycle`(856)、`erased_actors`(862)、`failed_login_attempts`(870)、`notification_read_cursors`(874)、`sync_cursor_handles`(879)、`consent_cells`(889)、`sovereign_deployment`(895)、`retention_policies`(900)、`organizations`(913)、`space_moderation_policies`(923)、`did_resolver`(924)、`subscribe_reconnect_gate`(949)、`anchorer_signing_key_origin`(969) 等（行号取自 `sed -n '836,990p'` 内偏移）。
- 这些字段全部 `pub`，且与真正的持久化后端（`persistence`）形成**双重事实来源**：同一类数据（如 organizations、retention policy）既可能落在 PG，又有一份 `Arc<Mutex<BTreeMap>>` 内存副本。

### 影响
- 全 `pub` 字段意味着任意 handler 可直接读写任意子状态，没有不变量守门，难以推理一致性。
- 内存影子表与持久化后端并存 → 重启丢失 / 多副本不一致 / 难以横向扩展（单进程内存即真相，与"参考服务端可水平部署"目标冲突）。
- god-object 让单元测试构造 `AppState` 极其笨重（参见各 handler 测试里大段 `AppState{ ... }` 字面量，如 `src/routing/mod.rs:1598`、`2450` 等处都要把每个字段填一遍）。

### 建议
- 将语义相关的影子表收敛为有方法的子组件（如 `IdentityRuntime`、`ModerationRuntime`），字段降为 `pub(crate)` 或私有 + 访问方法，集中维护不变量。
- 把可持久化的内存表（organizations / retention / consent 等）迁入 `PersistenceStore`，`AppState` 不再持有第二份事实来源；纯进程内瞬态（广播 channel、reconnect gate）才留在 `AppState`。
- 提供 `AppState::for_test(...)` builder，消除测试里逐字段构造。

### 复验结论
已重新打开 `src/state.rs:836-990` 核对：38 个 `pub` 字段、约 20 个 `Arc<Mutex<…>>` 影子表与 `persistence`/`projection` 并列属实。`std::sync::Mutex` 选型问题在报告 12 单列。

---

## 问题 4：`src/schema.rs`（Diesel `table!` schema）是死模块，未被任何代码引用

### 严重级别
P2

### 证据
- `src/schema.rs:1` 起为 `diesel::table!{ ... }` 定义，共 29 张表（`grep -c 'diesel::table!'` = 29）。
- `src/lib.rs:27` `pub mod schema;` 公开导出。
- 但全仓检索 `crate::schema` / `use ...schema::` / `accounts::table` / `::dsl::` 在**非测试代码中零命中**（唯一含 "schema" 的 `use` 是 `src/routing/events/operations.rs:26` 的 `contrix_sdk::schema::event_payload_validator_catalog`，与本模块无关）。
- 实际查询全部走原始 SQL：`grep -c 'sql_query' src/persistence.rs` = 144，`QueryableByName` = 44；而 Diesel 类型化 DSL（`::table` / `insert_into` / `.filter(`）合计仅 23 处，且经核对均不引用 `crate::schema` 生成的表模块。

### 影响
- 290+ 行 `table!` 定义随 schema 变更需手工同步，却没有任何编译期校验受益方 —— 维护成本无收益。
- 误导后来者以为查询是类型化 Diesel DSL，实际是裸 SQL。
- schema drift：`schema.rs` 与 `migrations/` 可能不一致而无人察觉（没有编译失败兜底）。

### 建议
- 二选一：(a) 删除 `src/schema.rs` 与 `lib.rs:27` 的导出（最省事，承认本项目走裸 SQL 路线）；或 (b) 真正采用类型化 DSL（见报告 07 问题 1），让 `schema.rs` 产生编译期价值。鉴于已有 144 处裸 SQL，(a) 成本更低，(b) 收益更大但工作量大。
- 若保留，至少加 `diesel print-schema` 的 CI 校验，确保与迁移一致。

### 复验结论
已重新打开 `src/schema.rs:1-20`、`src/lib.rs:27`，并复跑 `grep -rn 'crate::schema\|accounts::\|::dsl::' src` 确认非测试零命中。死模块结论成立。

---

## 问题 5：`reducer` 存在两套并行投影路径（inline `apply_*` 缓存 vs LatticeRegistry/cell 模型）尚未收敛

### 严重级别
P2

### 证据
- `src/reducer.rs:1-24` 模块头明确写道：`ProjectionState` 的结构化字段（`messages`/`reactions`/`read_cursors` 等）是"**a convenience cache populated from the durable Event-Envelope ingestion path that pre-dates the Move/Anchor model**"，并称"As Anchor projection lands, the structured fields migrate to a single `cells` map"。
- 代码里两条路径并存：`ProjectionState::apply`（3619，inline `APPLY_REGISTRY` 分派）与 `apply_via_lattice_registry`（3650，先查 `LatticeRegistry::lookup_for_event_kind`，命中后仍回落到 inline `self.apply`，见 3668-3678 的注释"the registry just declares which event kinds it owns"）。
- 即：协议-canonical 的 cell/lattice 路径目前只做"声明哪些 event kind 归它管"，真正的投影仍由 pre-dating 的 inline 结构化字段完成 —— 迁移半途。

### 影响
- 两套真相（结构化字段缓存 + cell 模型）长期并存增加心智负担与不一致风险。
- 新对象/新 event kind 要同时考虑"该走 inline 还是 lattice"，文档化的"将来迁移到单一 cells map"是技术债。

### 建议
- 制定收敛计划并在代码中以 tracking issue 标注：明确每个对象族何时从结构化字段迁往 `cells`。短期至少加断言/测试保证两条路径对同一 operation 的可观察效果一致。
- 在 `reducer/mod.rs` 顶部把"迁移状态矩阵"（哪些 kind 已 cell 化、哪些仍 inline）显式列出，避免靠埋在万行文件里的注释传达。

### 复验结论
已重新打开 `src/reducer.rs:1-24`、`:3619-3627`、`:3650-3678` 核对：两路径并存与"待迁移"注释属实。

---

## 问题 6：`reducer.rs` 与 `reducer/` 子目录并存，命名/边界易混淆

### 严重级别
P3

### 证据
- 同时存在文件 `src/reducer.rs`（10560 行，含 `pub mod lattice_kinds; pub mod mls; pub mod realm_links; pub mod realm_policy_server; pub mod registry;`，见 `:26-31`）与目录 `src/reducer/`（`lattice_kinds.rs`/`mls.rs`/`realm_links.rs`/`realm_policy_server.rs`/`registry.rs`）。
- 这是 Rust 2018+ 合法布局（`reducer.rs` 作为模块根、`reducer/` 放子模块），但根文件本身又塞了 8000+ 行实现（见问题 1），使"`reducer.rs` 到底是模块入口还是实现大本营"边界模糊。

### 影响
- 读者预期 `reducer.rs` 是薄入口（`mod` 声明 + 总分派），实际它是最大的实现文件，定位成本高。
- `mls`/`realm_links` 已拆入子目录，但 message/relation/membership 等核心 reducer 仍留在根文件，拆分标准不一致。

### 建议
- 配合问题 1：把根文件瘦身为 `reducer/mod.rs`（仅 `ProjectionState` 定义、`pub mod` 声明、`apply`/`apply_batch`/`apply_via_lattice_registry` 总分派），其余实现一律下沉到 `reducer/<domain>.rs`，使拆分标准统一。

### 复验结论
已重新打开 `src/reducer.rs:26-31` 与 `ls src/reducer/` 核对：根文件 + 子目录并存、根文件含大量实现属实。

---

## 附：未发现明显问题的方面（供交叉参考）

- `routing/` 目录按领域（events / federation / identity / interop / spaces / admin / system / extensions / access / conformance）切分清晰，子模块大量使用 `pub(crate)`（`src/routing/mod.rs:18-37`），可见性收敛良好。
- 错误码组织集中、规范：`src/error.rs` 把 wire 错误码与 reason code 统一从 `contrix_sdk::error` re-export，`AppError`（509）是单一典型 error 类型，未见错误类型散乱。
- 未发现 v2+ 协议版本漂移（`v2` 命中均为内部投影/线形描述或测试 fixture，非 soland 自定义协议版本，详见报告 12）。
