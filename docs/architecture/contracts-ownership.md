# Soland contracts 类型所有权登记

本表记录阶段 0 及后续新增公共 DTO 的逐项审计。审计范围包括
`arkret-spec/spec/v1/artifacts`、`arkret-rust-sdk` 的公开 wire 类型以及真实跨仓消费者。
结论是：这些类型均未命中 Arkret spec wire 定义，属于部署本地的管理面或集成契约，
因此保留在 `soland-contracts`；没有需要迁回 SDK 的本地重复定义。

| 模块 | 类型 | 所有权 | 已确认消费者 | spec/SDK 对照结论 |
| --- | --- | --- | --- | --- |
| `admin::account_localparts` | `AccountLocalpartView` | local contract | Soland、Sodmin | `/_soland/admin` 本地账号映射投影；未命中 spec wire 类型 |
| `admin::account_localparts` | `AccountLocalpartListOutcome` | local contract | Soland、Sodmin | 部署本地列表 envelope；未命中 spec wire 类型 |
| `admin::account_localparts` | `AccountLocalpartAddRequestBody` | local contract | Soland、Sodmin | 部署本地管理命令；未命中 spec wire 类型 |
| `admin::account_localparts` | `AccountLocalpartMutationOutcome` | local contract | Soland、Sodmin | 部署本地变更结果；未命中 spec wire 类型 |
| `admin::handles` | `AdminHandleRecord` | local contract | Soland、Sodmin | 部署本地 handle 管理投影；未命中 spec wire 类型 |
| `admin::handles` | `AdminHandleAuditEvent` | local contract | Soland、Sodmin | 部署本地 handle 审计投影；未命中 spec wire 类型 |
| `admin::handles` | `AdminHandleListOutcome` | local contract | Soland、Sodmin | 部署本地 handle 列表 envelope；未命中 spec wire 类型 |
| `admin::handles` | `AdminHandleAuditListOutcome` | local contract | Soland、Sodmin | 部署本地 handle 审计列表 envelope；未命中 spec wire 类型 |
| `admin::handles` | `AdminHandleReassignBody` | local contract | Soland、Sodmin | 部署本地 handle 管理命令；未命中 spec wire 类型 |
| `admin::handles` | `AdminHandleRevokeBody` | local contract | Soland、Sodmin | 部署本地 handle 管理命令；未命中 spec wire 类型 |
| `admin::device_signing_directory` | `DeviceSigningKeyDirectoryQueryRequestBody` | local contract | Soland、Coauth | 产品间 signing-key directory 查询；字段复用 SDK 类型，整体未命中 spec wire 类型 |
| `admin::device_signing_directory` | `AuthorizedDeviceSigningKey` | local contract | Soland、Coauth | 产品间 signing-key directory 投影；字段复用 SDK 类型，整体未命中 spec wire 类型 |
| `admin::device_signing_directory` | `DeviceSigningKeyDirectoryOutcome` | local contract | Soland、Coauth | 产品间 signing-key directory 响应；字段复用 SDK 类型，整体未命中 spec wire 类型 |
| `admin::invite_tokens` | `AdminInviteTokenItem` | local contract | Soland、Sodmin | Realm invite 状态的只读管理投影；DTO 整体未命中 spec wire 类型 |
| `admin::queries` | `AdminActor` | local contract | Soland、Sodmin | `/_soland/admin` 操作面投影；字段复用 SDK 类型，整体未命中 spec wire 类型 |
| `admin::queries` | `AdminActorList` | local contract | Soland、Sodmin | `/_soland/admin` 操作面列表 envelope；未命中 spec wire 类型 |
| `admin::queries` | `AdminAuditEntry` | local contract | Soland、Sodmin | `/_soland/admin` 操作面审计投影；未命中 spec wire 类型 |
| `admin::queries` | `AdminAuditList` | local contract | Soland、Sodmin | `/_soland/admin` 操作面列表 envelope；未命中 spec wire 类型 |
| `admin::queries` | `CapabilityGrantState` | local contract | Soland、Sodmin | `/_soland/admin` 操作面枚举；未命中 spec wire 类型 |
| `admin::queries` | `CapabilitySummary` | local contract | Soland、Sodmin | `/_soland/admin` 操作面投影；字段复用 SDK 类型，整体未命中 spec wire 类型 |
| `admin::queries` | `AdminCapabilityList` | local contract | Soland、Sodmin | `/_soland/admin` 操作面列表 envelope；未命中 spec wire 类型 |
| `admin::queries` | `AdminDevice` | local contract | Soland、Sodmin | `/_soland/admin` 操作面投影；字段复用 SDK 类型，整体未命中 spec wire 类型 |
| `admin::queries` | `AdminDeviceList` | local contract | Soland、Sodmin | `/_soland/admin` 操作面列表 envelope；未命中 spec wire 类型 |
| `admin::seal` | `NotaryKind` | local contract | Soland、Sodmin | SDK 有领域 notary 值，但无此管理面投影视图 |
| `admin::seal` | `BottomKind` | SDK re-export | Soland、Sodmin | 直接复用 `arkret-wire` 的规范枚举，不在本 crate 重复定义 |
| `admin::seal` | `BottomKindExt` | local pure helper | Soland、Sodmin | 仅提供产品管理 UI 标签/解析辅助，不改变 SDK wire 枚举 |
| `admin::seal` | `AdminNotaryValue` | local contract | Soland、Sodmin | 未命中 spec wire 类型 |
| `admin::seal` | `SubmitControlMoveOutcome` | local contract | Soland | Bottom repair 的部署本地结果；未命中 spec wire 类型 |
| `admin::seal` | `BottomCandidateHead` | local contract | Soland、Sodmin | 未命中 spec wire 类型 |
| `admin::seal` | `BottomEntry` | local contract | Soland、Sodmin | 未命中 spec wire 类型 |
| `admin::seal` | `BottomRepairStrategy` | local contract | Soland | 只描述部署本地恢复前置检查；未命中 spec wire 类型 |
| `admin::seal` | `BottomRepairRequestBody` | local contract | Soland | 只描述部署本地恢复前置检查；未命中 spec wire 类型 |
| `admin::seal` | `SealLeaf` | local contract | Soland、Sodmin | 未命中 spec wire 类型 |
| `admin::seal` | `SealChainSnapshot` | local contract | Soland、Sodmin | 未命中 spec wire 类型 |
| `admin::seal` | `SealPruneRequestBody` | local contract | Soland | 部署本地历史存储 GC；未命中 spec wire 类型 |
| `admin::seal` | `SealPruneOutcome` | local contract | Soland | 部署本地历史存储 GC；未命中 spec wire 类型 |
| `admin::seal` | `SealPruneDiagnostics` | local contract | Soland | 部署本地历史存储 GC；未命中 spec wire 类型 |
| `admin::seal` | `MultisigPendingEntry` | local contract | Soland、Sodmin | 未命中 spec wire 类型 |
| `admin::seal` | `MultisigPendingOutcome` | local contract | Soland、Sodmin | 未命中 spec wire 类型 |
| `admin::collection` | `RealmClass` | local contract | Soland、Sodmin | `/_soland/admin` Realm 行内分类封闭枚举；未命中 spec wire 类型 |
| `admin::collection` | `AdminRealmItem` | local contract | Soland、Sodmin | `GET /_soland/admin/{resource}`（realms）与 `/_soland/admin/realms/{realm_id}` 详情投影；字段复用 SDK 类型，整体未命中 spec wire 类型 |
| `admin::collection` | `SpaceHealth` | local contract | Soland、Sodmin | Space 容器生命周期封闭枚举；未命中 spec wire 类型 |
| `admin::collection` | `AdminSpaceRow` | local contract | Soland、Sodmin | `/_soland/admin/spaces` 集合行投影；未命中 spec wire 类型 |
| `admin::collection` | `AdminFederationOperation` | local contract | Soland、Sodmin | `/_soland/admin/federation` 联邦操作行投影；字段复用 SDK 类型，整体未命中 spec wire 类型 |
| `admin::collection` | `AdminMediaRow` | local contract | Soland、Sodmin | `/_soland/admin/media` 集合行投影；未命中 spec wire 类型 |
| `admin::media` | `AdminMediaBucket` | local contract | Soland、Sodmin | `/_soland/admin/media/statistics` 聚合分桶；Sodmin 经 `AdminMediaStatistics` 内嵌字段消费；未命中 spec wire 类型 |
| `admin::media` | `AdminMediaByActorRow` | local contract | Soland、Sodmin | `/_soland/admin/media/{statistics,by-actor}` 按上传者聚合行；Sodmin 经 `AdminMediaStatistics`/`AdminMediaByActorList` 内嵌消费；未命中 spec wire 类型 |
| `admin::media` | `AdminMediaStatistics` | local contract | Soland、Sodmin | `GET /_soland/admin/media/statistics` 响应；未命中 spec wire 类型 |
| `admin::media` | `AdminMediaByActorList` | local contract | Soland、Sodmin | `GET /_soland/admin/media/by-actor` 列表 envelope；未命中 spec wire 类型 |
| `admin::media` | `MediaServiceFocus` | SDK contract | Soland、Sodmin | 直接使用 `arkret-models-collaboration` 中 spec `event-payload.schema.json` `$defs/media_service_focus` 的唯一实现 |
| `admin::media` | `AdminRealmMediaService` | local contract | Soland、Sodmin | `GET /_soland/admin/realms/{realm_id}/media-service` 只读投影；未命中 spec wire 类型 |
| `admin::policy` | `PolicyEffect` | SDK re-export | Soland、Sodmin | 直接复用 `arkret-wire` 的规范枚举（spec `governance-objects.md` `default_effect` / `policy.schema.json` `$defs/policy_effect` 四值闭集 `allow`/`deny`/`quarantine`/`require_review`），不在本 crate 重复定义 |
| `admin::policy` | `AdminPolicyPayload` | local contract | Soland、Sodmin | `/_soland/self/policies` 文档决策体；`resource` 永久为 opaque operator data，Sodmin 不得解析或展示其子结构；approval evidence、audit 与 policy decision 只走既有 typed API；未命中 spec wire 类型 |
| `admin::policy` | `AdminPolicyDocument` | local contract | Soland、Sodmin | `GET /_soland/self/policies` 文档投影；未命中 spec wire 类型 |
| `admin::policy` | `AdminPolicyDocumentPage` | local contract | Soland、Sodmin | `GET /_soland/self/policies` 分页 envelope；未命中 spec wire 类型 |
| `admin::policy` | `UpsertPolicyDocumentRequestBody` | local contract | Soland、Sodmin | `POST /_soland/self/policies` 部署本地管理命令；未命中 spec wire 类型 |
| `admin::server` | `AdminServerInfo` | local contract | Soland、Sodmin | `GET /_soland/admin/server/info` 节点信息投影；未命中 spec wire 类型 |
| `admin::server` | `AdminServerStats` | local contract | Soland、Sodmin | `GET /_soland/admin/server/stats` 计数快照；未命中 spec wire 类型 |
| `admin::server` | `AdminServerStatusCounts` | local contract | Soland、Sodmin | Sodmin 经 `AdminServerStatus.counts` 内嵌字段消费；未命中 spec wire 类型 |
| `admin::server` | `AdminServerStatus` | local contract | Soland、Sodmin | `GET /_soland/admin/server/status` 可达性探针响应；未命中 spec wire 类型 |
| `admin::service_routes` | `AdminServiceRouteSummary` | local contract | Soland、Sodmin | `GET /_soland/admin/service-routes` 列表行；Sodmin 经 `AdminServiceRouteList` 内嵌消费；字段复用 SDK 类型，整体未命中 spec wire 类型 |
| `admin::service_routes` | `AdminServiceRouteList` | local contract | Soland、Sodmin | `GET /_soland/admin/service-routes` 列表 envelope；未命中 spec wire 类型 |
| `admin::service_routes` | `AdminServiceMethodState` | local contract | Soland、Sodmin | Sodmin 经 `AdminServiceRouteDetail.method_state` 内嵌字段消费；未命中 spec wire 类型 |
| `admin::service_routes` | `AdminServiceRouteCurrent` | local contract | Soland、Sodmin | Sodmin 经 `AdminServiceRouteDetail.current_route` 内嵌字段消费；未命中 spec wire 类型 |
| `admin::service_routes` | `AdminServiceRouteCache` | local contract | Soland、Sodmin | Sodmin 经 `AdminServiceRouteDetail.cache` 内嵌字段消费；未命中 spec wire 类型 |
| `admin::service_routes` | `AdminServiceRouteQuarantine` | local contract | Soland、Sodmin | Sodmin 经 `AdminServiceRouteDetail.quarantine` 内嵌字段消费；未命中 spec wire 类型 |
| `admin::service_routes` | `AdminServiceRouteDetail` | local contract | Soland、Sodmin | `GET /_soland/admin/service-routes/{service_id}/{service_kind}` 详情投影；字段复用 SDK 类型，整体未命中 spec wire 类型 |

若以后出现同名或等价的规范类型，必须先在 `arkret-rust-sdk` 实现，并用规范固定样例做
canonical JSON 字节对比，再从本表和 `soland-contracts` 删除相应本地契约。
