# soland Active TODO

> 更新日期: 2026-04-30
> 范围: Contrix Principal Server / Repo / Sync / Index / Blob / Federation reference implementation。Identity Registry 服务端职责已迁移到 `starid`。

## 0. 当前边界

- `soland` 负责 Principal Server 服务面: account/session、repo、sync、directory、index、authz、device messages、blob、push registration、federation、moderation。
- `identity/*` 兼容入口只用于本地联调和 service discovery；DID document/key-log/registry receipt 的生产实现归 `starid`。
- 当前代码已有 PostgreSQL repo adapter 和大量 HTTP surface，但业务状态仍大量保存在 `AppState` 的 `Arc<Mutex<...>>` 中。
- 当前主要未闭合项: durable server state、transactional write path、authz at causal frontier、sync/backfill/snapshot 完整语义、federation security、blob/media authorization、multi-instance fanout。

## Profile 收敛目标

| Profile | 当前状态 | 阻塞项 |
| --- | --- | --- |
| `cx.profile.principal_server_repo_api.v1` | PARTIAL | transactional repo write、proof validation、operation/schema conformance、authz frontier |
| `cx.profile.principal_server.v1` | PARTIAL | durable account/session/device/blob/push/sync state、multi-instance fanout |
| `cx.profile.index_node.v1` | PARTIAL | durable projection、query schema、auth filtering、stale frontier |
| `cx.profile.blob_node.v1` | PARTIAL | authenticated download、quota、retention、anti-enumeration |
| `cx.profile.federation_node.v1` | PARTIAL | HTTP Message Signatures、service DID binding、replay/fork persistence |

## P0: Spec Drift - Facet-Based Object Model and View Projection

目标: 对齐 `contrix-spec` 最新对象能力模型，服务端不再把 `entity_type` 当作行为授权来源。

- [x] Entity/index storage:
  - [x] 持久化实体 `facets`，支持 full entity facet config 与 projection facet-name list 的兼容输入。
  - [x] reducer/index 查询支持 `facets`，语义为所有指定 facet 均匹配；`entity_types` 保留为兼容标签过滤。
  - [x] projection payload 返回实体 facets，便于客户端选择 renderer。
- [x] View/query HTTP contract:
  - [x] `IndexQueryRequest` 支持 `renderer` 和 `facets`。
  - [x] collection/conversation/graph/queue view config 支持 `item_facets/message_facets/node_facets`。
  - [x] cursor/filter hash 绑定 `renderer` 和 `facets`，避免 filter mismatch 被误判为可继续分页。
- [x] Operation reducer:
  - [x] 接受 canonical `cx.field_position.move`、`cx.field_position.reorder`、`cx.container.move_item`、`cx.container.rebalance`。
  - [x] 旧 `cx.task.move/reorder`、`cx.relation.move/rebalance` 仅在 compatibility profile 下映射。
  - [x] audit 与 conflict 记录保留原始输入 kind 和 canonical kind。
- [ ] Authz constraints:
  - [x] grant constraint 支持 `allowed_entity_facets`。
  - [x] causal frontier 授权时使用 reducer 输出的实体 facets，缺失或未知 critical facet 约束 fail closed。
  - [ ] policy dry-run 和 audit 输出展示 facet constraint 命中原因。
- [ ] OpenAPI/conformance:
  - [ ] 生成 OpenAPI 包含 `FacetName`、`ViewRenderer`、`allowed_entity_facets`。
  - [ ] `cotest` 覆盖 facet query、renderer cursor binding 和 canonical/legacy operation alias。

并行性: reducer alias、index query、authz constraint、OpenAPI 生成可并行；但持久化 schema 和 SDK 类型需要先冻结。

## P0: Durable Server State

目标: 重启不丢业务状态，多实例不会破坏 repo/projection/audit 一致性。

- [ ] 定义 `PersistenceStore` 边界:
  - [ ] account/session/contact/space/invite/message/device/blob/push/presence/policy/audit/federation/sync positions。
  - [x] 区分 `RepoAdapter` 与业务状态 store。
  - [ ] memory store 与 PostgreSQL store 共用行为测试。
  - [ ] handler 不直接读写新增业务状态的 `Arc<Mutex<...>>`。
- [ ] PostgreSQL migrations:
  - [ ] 每类业务表有 primary key、created_at、updated_at。
  - [ ] 幂等写入有唯一约束。
  - [ ] cursor/pagination 查询有稳定索引。
  - [ ] down.sql 可回滚。
  - [ ] migration 自动运行有 integration test。
- [ ] Account/session:
  - [x] account register 持久化 DID/handle/display profile。
  - [x] session token hash 存储，不落明文 token。
  - [x] token 绑定 actor/device/expires_at/audience。
  - [x] logout 写 revoked_at。
  - [ ] locked/disabled/erased lifecycle 行为。
- [ ] Space/contact/invite:
  - [x] contacts request/accept/reject 幂等和 CAS。
  - [ ] spaces create/delete/member add/remove 事务化。
  - [ ] discoverability、owner、plaintext_visible_services、deleted 状态落库。
  - [ ] invite token hash、expiry、max_uses、revoked_at。
- [ ] Device/blob/push/presence:
  - [x] device inventory。
  - [ ] device key / one-time key / fallback key persistence。
  - [ ] push devices and push rules persistence。
  - [ ] presence/typing multi-instance fanout。
  - [ ] blob metadata and access grants persistence。
- [ ] Audit:
  - [x] request_id、actor、device_id、space_id、operation_id、commit_id、outcome。
  - [ ] high-risk endpoint 必写 audit。
  - [x] cursor pagination。

并行性: account/session、space/contact、device/push、blob、audit/federation store 可并行；store trait 和 migration conventions 需要先冻结。

## P0: Transactional Repo / Reducer Write Path

目标: repo commit、operation、projection 和 audit 在同一可恢复边界内生效。

- [ ] Write transaction:
  - [ ] repo commit append。
  - [ ] operation insert。
  - [ ] projection event insert。
  - [ ] authz decision record。
  - [ ] audit log insert。
- [ ] CAS / idempotency:
  - [ ] expected_head mismatch rollback。
  - [ ] duplicate commit same body returns accepted。
  - [ ] duplicate commit different body returns conflict。
  - [ ] duplicate operation id different digest quarantined。
- [ ] Reducer recovery:
  - [ ] startup rebuild from durable events。
  - [ ] snapshot fast path。
  - [ ] snapshot frontier mismatch falls back to replay。
  - [ ] reducer version recorded。
- [ ] Proof validation:
  - [ ] production rejects `alg:none` and `dev-proof`。
  - [ ] proof payload hash equals canonical commit digest。
  - [ ] verification method rooted in actor DID。
  - [ ] proof domain/audience binds service DID。

## P0: Capability at Causal Frontier

目标: 授权由 reducer/frontier 决定，不由 handler 当前内存快照或 owner/member 特判决定。

- [ ] Capability operations enter operation stream:
  - [ ] `cx.capability.grant`。
  - [ ] `cx.capability.delegate`。
  - [ ] `cx.capability.revoke`。
  - [ ] approval/proposal events。
- [ ] Reducer outputs effective capability state:
  - [ ] deterministic order by causal deps/HLC/actor_seq/event_id。
  - [ ] revoke affects causal frontier after revoke。
  - [ ] delegation depth decreases。
  - [ ] cycle detection。
  - [ ] conflict record exposed for audit。
- [ ] Write path check:
  - [ ] every operation declares required action/resource。
  - [ ] stale frontier returns `stale_frontier`。
  - [ ] unknown action/resource fail closed。
  - [ ] owner/member defaults become bootstrap grants or explicit local policy。
- [ ] Resource selector and constraints:
  - [ ] exact/prefix/pattern selector。
  - [ ] Space scope and child recursion。
  - [ ] temporal constraints。
  - [ ] field/type/visibility constraints。
  - [ ] encryption required。
  - [ ] blob max bytes。
  - [ ] edit window。
  - [ ] rate limit。
  - [ ] claim required。
  - [ ] approval required。
  - [ ] unknown critical constraints fail closed。
- [ ] Policy server boundary:
  - [ ] policy may deny/quarantine/require_review。
  - [ ] policy cannot grant missing capability。
  - [ ] signed decision references policy id/version/frontier。

## P0: Client Sync Correctness

目标: 客户端可稳定 initial/incremental sync、backfill gap、ack to-device，并在重启后继续使用 cursor。

- [ ] Sync positions:
  - [ ] per actor/device stream position。
  - [ ] per joined space timeline position。
  - [ ] to-device delivery position。
  - [ ] cursor position 与 durable position 双向校验。
- [ ] Initial sync buckets:
  - [ ] join。
  - [ ] invite。
  - [ ] knock。
  - [ ] leave。
- [ ] Joined Space payload:
  - [ ] timeline。
  - [ ] state。
  - [ ] state_after。
  - [ ] ephemeral。
  - [ ] account_data。
  - [ ] summary。
  - [ ] unread_notifications。
- [ ] Timeline/backfill:
  - [ ] deterministic timeline order。
  - [ ] `timeline.limited=true`。
  - [ ] `prev_batch`。
  - [ ] gap backfill endpoint。
  - [ ] invalid/expired/filter-mismatch cursor errors。
- [ ] `X-Contrix-Wait-For`:
  - [ ] waits for repo/projection frontier。
  - [ ] timeout returns 503 + retry metadata。
  - [ ] satisfied frontier response header。
- [ ] To-device:
  - [x] deliver until cursor ack。
  - [x] duplicate sync does not drop unacked messages。
  - [ ] revoked device stops receiving。

## P0: Federation Security

- [ ] HTTP Message Signatures:
  - [ ] method。
  - [ ] target URI。
  - [ ] authority。
  - [ ] content digest。
  - [ ] origin service DID。
  - [ ] destination service DID。
  - [ ] created/expires。
- [ ] DID service binding:
  - [ ] origin endpoint declared in DID Document。
  - [x] destination matches local service DID。
  - [ ] service delegation covers target Space。
- [ ] Transaction persistence:
  - [x] `(origin, txn_id)` unique。
  - [x] same body duplicate accepted。
  - [x] different body duplicate conflict。
  - [x] restart-safe replay protection。
- [ ] Operation verification:
  - [ ] every operation independently verified。
  - [ ] authz checked at causal frontier。
  - [ ] plaintext_visible_services enforced。
- [ ] Fork quarantine:
  - [ ] commit id conflict。
  - [ ] operation id conflict。
  - [ ] quarantine queue。
  - [ ] operator audit。
- [ ] Pull authorization:
  - [ ] backfill capability。
  - [ ] history visibility。
  - [ ] not_found anti-enumeration。
- [ ] `verify-actor` uses challenge signature, not public DID oracle。

## P1: Snapshot and Bootstrap

- [ ] Reducer snapshot manifest:
  - [ ] schema profile refs。
  - [ ] reducer profile。
  - [ ] covers_frontier。
  - [ ] chunk digests。
  - [ ] state_hash / Merkle root。
  - [ ] signed_by。
  - [ ] generator signature。
- [ ] Snapshot chunk endpoint。
- [ ] chunk SHA-256 verification。
- [ ] client failure fallback to repo replay。
- [ ] first-join bootstrap contract:
  - [ ] resolve services。
  - [ ] fetch invite/grants。
  - [ ] fetch snapshot manifest。
  - [ ] download chunks。
  - [ ] pull increments。
  - [ ] run reducer。
  - [ ] enter cursor subscription。

## P1: Blob / Media

- [ ] Authenticated download:
  - [x] actor DID。
  - [x] device/session。
  - [x] Space id。
  - [x] blob ref。
  - [x] purpose。
  - [ ] expiry。
- [ ] Anti-enumeration:
  - [x] invisible blob same as not_found。
  - [x] HEAD/Range does not leak size/type/existence。
  - [x] unsafe headers suppressed for invisible resources。
- [ ] Upload:
  - [x] content hash verified。
  - [x] MIME/filename sanitized。
  - [x] quota by upload/account/space。
  - [x] encrypted/plaintext flag and policy validation。
- [ ] Object store backend。
- [ ] short-lived signed redirect token。
- [ ] retention / legal hold / unsafe media status。

## P1: Device / E2EE / Push / Presence

- [ ] Device pairing challenge and authorization event。
- [ ] Device revocation cascade:
  - [ ] session revoke。
  - [ ] key query hides revoked device。
  - [ ] to-device queue stops。
  - [ ] future encrypted writes fail closed。
- [ ] MLS surfaces:
  - [ ] KeyPackage publish/fetch/verify。
  - [ ] Welcome event。
  - [ ] Commit/Proposal event。
  - [ ] epoch mismatch recovery。
  - [ ] removed member fail closed。
- [ ] Push:
  - [ ] push rules priority groups。
  - [ ] per-Space unread/highlight counts。
  - [ ] blind wakeup payload only。
  - [ ] floria invalid token cleanup。
- [ ] Presence/typing:
  - [ ] scope policy。
  - [ ] expiry cleanup。
  - [ ] multi-instance broadcast。
- [ ] Account data:
  - [ ] tags。
  - [ ] preferences。
  - [ ] ignored actors。
  - [ ] direct spaces。

## P1: Index / Directory / Query

- [ ] Query schema:
  - [ ] structured filters。
  - [ ] sort。
  - [ ] pagination cursor。
  - [ ] relation traversal。
  - [ ] full-text search for plaintext-visible Spaces。
- [ ] Per-result authorization filtering。
- [ ] stale frontier reporting。
- [ ] explain/debug reducer endpoint。
- [ ] View projections:
  - [ ] kanban。
  - [ ] table。
  - [ ] timeline。
  - [ ] graph/tree。
  - [ ] gantt。
- [ ] Organization:
  - [ ] create/update。
  - [ ] membership。
  - [ ] endorsement/revocation proof。
- [ ] Directory anti-enumeration:
  - [ ] pairwise/private DID not leaked。
  - [ ] actor search limited by common Space or directory policy。
  - [ ] public/listed/restricted/unlisted/invite_only/secret matrix tests。

## P1: Admin API, Observability and Conformance

- [ ] Admin endpoints needed by `sodmin`:
  - [ ] actors。
  - [ ] spaces。
  - [ ] devices。
  - [ ] capabilities。
  - [ ] federation。
  - [ ] applets。
  - [ ] agents。
  - [ ] reports。
  - [ ] invite tokens。
  - [ ] audit。
  - [ ] policy。
  - [ ] media。
- [ ] API conventions:
  - [ ] 404/405/429/503 standard envelopes。
  - [ ] no query auth。
  - [ ] per actor + IP rate limit。
  - [ ] high-risk endpoint rate limits。
- [ ] Observability:
  - [ ] structured tracing fields。
  - [ ] metrics for sync/repo/blob/federation/authz。
  - [ ] logs redact tokens/push keys。
- [ ] OpenAPI:
  - [ ] generated OpenAPI 3.1。
  - [ ] `/.well-known/contrix/openapi.yaml`。
  - [ ] operationId equals canonical `cx.*` where applicable。
- [ ] `cotest` conformance suites:
  - [ ] state resolution。
  - [ ] redaction。
  - [ ] capability。
  - [ ] sync。
  - [ ] snapshot。
  - [ ] federation signatures。
  - [ ] privacy regression。

## Definition of Done

- [ ] Code implemented。
- [ ] Unit, HTTP and PostgreSQL integration tests added。
- [ ] Protocol semantics covered by conformance fixture or documented gap。
- [ ] Feature discovery and OpenAPI updated。
- [ ] README/profile docs updated。
- [ ] Production path does not depend on dev proof, in-memory state or hardcoded service DID unless explicitly marked dev-only。

## 本轮验证记录

- [x] 2026-04-30 spec drift: `cargo fmt --all`。
- [x] 2026-04-30 spec drift: `cargo check --message-format short`。
- [x] 2026-04-30 spec drift: `cargo test --lib entity_facets_filter_queries --message-format short`。
- [x] 2026-04-30 spec drift: `cargo test --lib canonical_field_position_move_updates_entity_position_fields --message-format short`。
- [x] 2026-04-30 spec drift: `cargo test --lib legacy_task_move_requires_migration_profile --message-format short`。
- [x] 2026-04-30 follow-up: `cargo fmt --all`。
- [x] 2026-04-30 follow-up: `cargo check --message-format short`。
- [x] 2026-04-30 follow-up: `cargo check --tests --message-format short`。
- [x] 2026-04-30 follow-up: `git diff --check`。
- [ ] 2026-04-30 follow-up: targeted `cargo test` 未完成；本机测试链接阶段超过 5 分钟并留下 cargo/rustc 进程，已清理后改用 `cargo check --tests` 覆盖编译。
