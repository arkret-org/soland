//! Concrete `LatticeKind` impls + factory (SDK re-export shim).
//!
//! All `LatticeKind` impls and the [`default_lattice_registry`] /
//! [`build_sdk_cell_registry`] factories moved to
//! `arkret_lattice_registry` (SDK-8). This module is a thin
//! re-export shim. Existing callers
//! (`crate::reducer::lattice_kinds::default_lattice_registry()`,
//! `build_sdk_cell_registry()`) keep working without changes.

// Re-export the individual cell-family impl structs as well so any
// soland test that referenced them by name (e.g. `ViewCreate`,
// `ViewUpdate`, `ViewReconcile` mentioned in `routing/events/operations.rs`
// comments) continues to compile.
pub use arkret_lattice_registry::{
    AccountStatus, AgentKey, AgentStatus, CallState, CallSummary, CapabilityDelegate,
    CapabilityDerived, CapabilityGrant, CircleCreate, CircleMember, CircleTombstone, ConsentGrant,
    ContactFactLog, CoveredSeals, CrossSigningPublish, CrossSigningReset, DeviceAuthorized,
    DeviceListUpdate, DevicePushRoute, DirectConversationBinding, KeyBackupActiveSeries,
    MemberIdentityLattice as MemberIdentity, MemberState, MimiRoomBinding, MlsEpoch, MorphStage,
    NotaryCell, PolicyRule, ProfileCreate, RealmArchive, RealmAssetPrivacyPolicy, RealmCreate,
    RealmDeliveryBindingPolicy, RealmDestroy, RealmDisappearingPolicy, RealmDiscovery, RealmFreeze,
    RealmHistorySharingPolicy, RealmHistoryVisibility, RealmInheritancePolicy, RealmJoinRule,
    RealmLink, RealmMediaService, RealmModerationPolicy, RealmOrganization,
    RealmPlaintextVisibleServices, RealmPolicy, RealmPolicyBundle, RealmPolicyServer,
    RealmPreviewPolicy, RealmReadReceiptPolicy, RealmSchema, RealmSearchPolicy, RealmTombstone,
    RealmUpgrade, SessionGrant, SpaceParent, StrandPosition, StrandStage, ViewCreate,
    ViewReconcile, ViewUpdate, build_sdk_cell_registry, default_lattice_registry,
    lattice_bindings_for_sdk_registry,
};
