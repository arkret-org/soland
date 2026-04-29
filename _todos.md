# soland Active TODO

> 更新日期: 2026-04-29
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

## P0: Durable Server State

目标: 重启不丢业务状态，多实例不会破坏 repo/projection/audit 一致性。

- [ ] 定义 `PersistenceStore` 边界:
  - [ ] account/session/contact/space/invite/message/device/blob/push/presence/policy/audit/federation/sync positions。
  - [ ] 区分 `RepoAdapter` 与业务状态 store。
  - [ ] memory store 与 PostgreSQL store 共用行为测试。
  - [ ] handler 不直接读写新增业务状态的 `Arc<Mutex<...>>`。
- [ ] PostgreSQL migrations:
  - [ ] 每类业务表有 primary key、created_at、updated_at。
  - [ ] 幂等写入有唯一约束。
  - [ ] cursor/pagination 查询有稳定索引。
  - [ ] down.sql 可回滚。
  - [ ] migration 自动运行有 integration test。
- [ ] Account/session:
  - [ ] account register 持久化 DID/handle/display profile。
  - [x] session token hash 存储，不落明文 token。
  - [x] token 绑定 actor/device/expires_at/audience。
  - [x] logout 写 revoked_at。
  - [ ] locked/disabled/erased lifecycle 行为。
- [ ] Space/contact/invite:
  - [ ] contacts request/accept/reject 幂等和 CAS。
  - [ ] spaces create/delete/member add/remove 事务化。
  - [ ] discoverability、owner、plaintext_visible_services、deleted 状态落库。
  - [ ] invite token hash、expiry、max_uses、revoked_at。
- [ ] Device/blob/push/presence:
  - [ ] device inventory。
  - [ ] device key / one-time key / fallback key persistence。
  - [ ] push devices and push rules persistence。
  - [ ] presence/typing multi-instance fanout。
  - [ ] blob metadata and access grants persistence。
- [ ] Audit:
  - [x] request_id、actor、device_id、space_id、operation_id、commit_id、outcome。
  - [ ] high-risk endpoint 必写 audit。
  - [ ] cursor pagination。

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
  - [ ] destination matches local service DID。
  - [ ] service delegation covers target Space。
- [ ] Transaction persistence:
  - [ ] `(origin, txn_id)` unique。
  - [ ] same body duplicate accepted。
  - [ ] different body duplicate conflict。
  - [ ] restart-safe replay protection。
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
  - [ ] content hash verified。
  - [ ] MIME/filename sanitized。
  - [ ] quota by upload/account/space。
  - [ ] encrypted/plaintext flag and policy validation。
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
