# Soland contracts 类型所有权登记

本表记录阶段 0 对改名前公共 DTO 的逐项审计。审计范围包括
`arkret-spec/spec/v1/artifacts`、`arkret-rust-sdk` 的公开 wire 类型以及真实跨仓消费者。
结论是：这些类型均未命中 Arkret spec wire 定义，属于部署本地的管理面或集成契约，
因此保留在 `soland-contracts`；没有需要迁回 SDK 的本地重复定义。

| 模块 | 类型 | 所有权 | 已确认消费者 | spec/SDK 对照结论 |
| --- | --- | --- | --- | --- |
| `admin::covered_seals` | `CoveredSealsSnapshot` | local contract | Soland、Sodmin | 未命中 spec wire 类型 |
| `admin::covered_seals` | `CoveredSealsAdvanceOutcome` | local contract | Soland、Sodmin | 未命中 spec wire 类型 |
| `admin::seal` | `NotaryKind` | local contract | Soland、Sodmin | SDK 有领域 notary 值，但无此管理面投影视图 |
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
