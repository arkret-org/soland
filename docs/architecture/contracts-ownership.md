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
| `admin::account_localparts` | `AccountLocalpartUpdateRequestBody` | local contract | Soland、Sodmin | 部署本地管理命令；未命中 spec wire 类型 |
| `admin::account_localparts` | `AccountLocalpartMutationOutcome` | local contract | Soland、Sodmin | 部署本地变更结果；未命中 spec wire 类型 |
| `admin::account_localparts` | `AccountLocalpartDeleteOutcome` | local contract | Soland、Sodmin | 部署本地删除结果；未命中 spec wire 类型 |
| `admin::covered_seals` | `CoveredSealsSnapshot` | local contract | Soland、Sodmin | 未命中 spec wire 类型 |
| `admin::covered_seals` | `CoveredSealsAdvanceOutcome` | local contract | Soland、Sodmin | 未命中 spec wire 类型 |
| `admin::handles` | `AdminHandleRecord` | local contract | Soland、Sodmin | 部署本地 handle 管理投影；未命中 spec wire 类型 |
| `admin::handles` | `AdminHandleAuditEvent` | local contract | Soland、Sodmin | 部署本地 handle 审计投影；未命中 spec wire 类型 |
| `admin::handles` | `AdminHandleListOutcome` | local contract | Soland、Sodmin | 部署本地 handle 列表 envelope；未命中 spec wire 类型 |
| `admin::handles` | `AdminHandleAuditListOutcome` | local contract | Soland、Sodmin | 部署本地 handle 审计列表 envelope；未命中 spec wire 类型 |
| `admin::handles` | `AdminHandleReassignBody` | local contract | Soland、Sodmin | 部署本地 handle 管理命令；未命中 spec wire 类型 |
| `admin::handles` | `AdminHandleRevokeBody` | local contract | Soland、Sodmin | 部署本地 handle 管理命令；未命中 spec wire 类型 |
| `admin::device_signing_directory` | `DeviceSigningKeyDirectoryQueryRequestBody` | local contract | Soland、Coauth | 产品间 signing-key directory 查询；字段复用 SDK 类型，整体未命中 spec wire 类型 |
| `admin::device_signing_directory` | `AuthorizedDeviceSigningKey` | local contract | Soland、Coauth | 产品间 signing-key directory 投影；字段复用 SDK 类型，整体未命中 spec wire 类型 |
| `admin::device_signing_directory` | `DeviceSigningKeyDirectoryOutcome` | local contract | Soland、Coauth | 产品间 signing-key directory 响应；字段复用 SDK 类型，整体未命中 spec wire 类型 |
| `admin::invite_tokens` | `CreateInviteTokenRequest` | local contract | Soland、Sodmin | 部署本地邀请令牌管理命令；未命中 spec wire 类型 |
| `admin::invite_tokens` | `AdminInviteTokenItem` | local contract | Soland、Sodmin | 部署本地邀请令牌管理投影；未命中 spec wire 类型 |
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
| `admin::seal` | `SelfSignViolation` | local contract | Soland、Sodmin | 未命中 spec wire 类型 |
| `admin::seal` | `NotaryReconfigRequestBody` | local contract | Soland、Sodmin | 未命中 spec wire 类型 |
| `admin::seal` | `SubmitControlMoveOutcome` | local contract | Soland、Sodmin | 未命中 spec wire 类型 |
| `admin::seal` | `BottomCandidateHead` | local contract | Soland、Sodmin | 未命中 spec wire 类型 |
| `admin::seal` | `BottomEntry` | local contract | Soland、Sodmin | 未命中 spec wire 类型 |
| `admin::seal` | `BottomRepairStrategy` | local contract | Soland、Sodmin | 未命中 spec wire 类型 |
| `admin::seal` | `BottomRepairRequestBody` | local contract | Soland、Sodmin | 未命中 spec wire 类型 |
| `admin::seal` | `SealLeaf` | local contract | Soland、Sodmin | 未命中 spec wire 类型 |
| `admin::seal` | `SealDagSnapshot` | local contract | Soland、Sodmin | 未命中 spec wire 类型 |
| `admin::seal` | `CompactionOutcome` | local contract | Soland、Sodmin | 未命中 spec wire 类型 |
| `admin::seal` | `CompactionRequestBody` | local contract | Soland、Sodmin | 未命中 spec wire 类型 |
| `admin::seal` | `SealPruneRequestBody` | local contract | Soland、Sodmin | 未命中 spec wire 类型 |
| `admin::seal` | `SealPruneOutcome` | local contract | Soland、Sodmin | 未命中 spec wire 类型 |
| `admin::seal` | `SealPruneDiagnostics` | local contract | Soland、Sodmin | 未命中 spec wire 类型 |
| `admin::seal` | `MultisigPendingEntry` | local contract | Soland、Sodmin | 未命中 spec wire 类型 |
| `admin::seal` | `MultisigPendingOutcome` | local contract | Soland、Sodmin | 未命中 spec wire 类型 |
| `integration::capability_fanout` | `CapabilityFanoutBody` | local contract | Coauth、Soland | 未命中 spec wire 类型 |
| `integration::capability_fanout` | `CapabilityFanoutResponse` | local contract | Coauth、Soland | 未命中 spec wire 类型 |
| `integration::capability_fanout` | `CapabilityFanoutAuthzState` | local contract | Coauth、Soland | 未命中 spec wire 类型 |

若以后出现同名或等价的规范类型，必须先在 `arkret-rust-sdk` 实现，并用规范固定样例做
canonical JSON 字节对比，再从本表和 `soland-contracts` 删除相应本地契约。
