//! Concrete [`LatticeKind`] implementations for the spec-normative cell
//! families.
//!
//! Per-cell-family Lattice runtime,
//! one impl per `cell_family` declared in
//! `contrix-spec/spec/v1/artifacts/registry/event-kind-registry.json`. The
//! `lattice` choice for each family mirrors the spec registry exactly (no
//! reinterpretation). Subject derivation reads typed effect-payload fields
//! per the spec's `cell_subject` field; `MissingSubjectField` is returned
//! if the typed field is absent.
//!
//! Coverage:
//! - **OrSet** (causal add/remove): consent.grant, capability.grant / delegate / derived,
//!   session.grant, device.authorized, device.list_update, covered_frontier (MLS).
//! - **CasRegister** (last-writer-wins, conflict→Bottom): space.policy, space.read_receipt_policy,
//!   space.history_visibility, space.join_rule, space.discovery, space.organization, space.upgrade,
//!   flow.position, place.parent, anchorer (Move/Anchor authority cell), mls_epoch.
//! - **Fsm** (legal transitions only): member.state.
//! - **OrderedLog** (per-issuer monotonic append): space.create, space.child, space.parent,
//!   account.status, policy.rule.
//! - **MvRegister** (concurrent multi-value): profile.create, view.create / update / reconcile,
//!   mimi.room_binding.
//!
//! Each impl is a ZST + trait impl. The factory [`default_lattice_registry`]
//! pre-registers every spec-declared family; downstream Move/Anchor receive
//! pipelines look up the matching impl by `effect.cell_family`.

use contrix_sdk::lattice::LatticeKind as SdkLatticeKind;
use contrix_sdk::state_res::{BottomMode, MemoryCellRegistry};
use serde_json::Value;

use crate::reducer::registry::{
    BottomPolicy, ComponentDescriptor, Criticality, LatticeKind, LatticeKindError, LatticeRegistry,
};

impl BottomPolicy {
    /// Translate this layer's `BottomPolicy` into the SDK state-res
    /// `BottomMode` that the `CellRegistry` uses to drive Move/Anchor
    /// receive-pipeline bottom handling. The two are 1:1 by design.
    pub fn to_sdk_bottom_mode(self) -> BottomMode {
        match self {
            Self::Reject => BottomMode::Reject,
            Self::Expose => BottomMode::Expose,
        }
    }
}

// ────────────────────────── Helper macros ──────────────────────────

macro_rules! singleton_lattice {
    ($struct_name:ident, $cell_family:expr, $lattice:expr, $bottom:expr, $criticality:expr) => {
        singleton_lattice!(
            $struct_name,
            $cell_family,
            $lattice,
            $bottom,
            $criticality,
            &[]
        );
    };
    (
        $struct_name:ident,
        $cell_family:expr,
        $lattice:expr,
        $bottom:expr,
        $criticality:expr,
        $event_kinds:expr
    ) => {
        pub struct $struct_name;
        impl LatticeKind for $struct_name {
            fn cell_family(&self) -> &'static str {
                $cell_family
            }
            fn lattice(&self) -> SdkLatticeKind {
                $lattice
            }
            fn bottom_policy(&self) -> BottomPolicy {
                $bottom
            }
            fn component(&self) -> ComponentDescriptor {
                ComponentDescriptor {
                    component_type: $cell_family,
                    component_version: 1,
                    criticality: $criticality,
                }
            }
            // Singleton: cell_subject is empty (one cell per Space).
            fn subject_for_effect(
                &self,
                _effect_payload: &Value,
            ) -> Result<Option<String>, LatticeKindError> {
                Ok(None)
            }
            fn event_kinds(&self) -> &'static [&'static str] {
                $event_kinds
            }
        }
    };
}

macro_rules! per_subject_lattice {
    (
        $struct_name:ident,
        $cell_family:expr,
        $lattice:expr,
        $bottom:expr,
        $criticality:expr,
        $subject_field:expr
    ) => {
        per_subject_lattice!(
            $struct_name,
            $cell_family,
            $lattice,
            $bottom,
            $criticality,
            $subject_field,
            &[]
        );
    };
    (
        $struct_name:ident,
        $cell_family:expr,
        $lattice:expr,
        $bottom:expr,
        $criticality:expr,
        $subject_field:expr,
        $event_kinds:expr
    ) => {
        pub struct $struct_name;
        impl LatticeKind for $struct_name {
            fn cell_family(&self) -> &'static str {
                $cell_family
            }
            fn lattice(&self) -> SdkLatticeKind {
                $lattice
            }
            fn bottom_policy(&self) -> BottomPolicy {
                $bottom
            }
            fn component(&self) -> ComponentDescriptor {
                ComponentDescriptor {
                    component_type: $cell_family,
                    component_version: 1,
                    criticality: $criticality,
                }
            }
            fn subject_for_effect(
                &self,
                effect_payload: &Value,
            ) -> Result<Option<String>, LatticeKindError> {
                effect_payload
                    .get($subject_field)
                    .and_then(Value::as_str)
                    .map(|s| Some(s.to_owned()))
                    .ok_or(LatticeKindError::MissingSubjectField {
                        cell_family: $cell_family,
                        field: $subject_field,
                    })
            }
            fn event_kinds(&self) -> &'static [&'static str] {
                $event_kinds
            }
        }
    };
}

// ────────────────────────── OrSet families ──────────────────────────
//
// Causal add/remove with tag uniqueness. `bottom = reject` (default) — an
// `OrSet` does not surface bottom in normal operation; rejection happens at
// op-validate time (e.g. malformed tag).

per_subject_lattice!(
    ConsentGrant,
    "cx.component.consent.grant.v1",
    SdkLatticeKind::OrSet,
    BottomPolicy::Reject,
    Criticality::Required,
    "consent_id",
    &["cx.consent.grant", "cx.consent.revoke"]
);

per_subject_lattice!(
    CapabilityGrant,
    "cx.component.capability.grant.v1",
    SdkLatticeKind::OrSet,
    BottomPolicy::Reject,
    Criticality::Required,
    "capability_id",
    &["cx.capability.grant", "cx.capability.revoke"]
);

per_subject_lattice!(
    CapabilityDelegate,
    "cx.component.capability.delegate.v1",
    SdkLatticeKind::OrSet,
    BottomPolicy::Reject,
    Criticality::Required,
    "capability_id",
    &["cx.capability.delegate"]
);

per_subject_lattice!(
    CapabilityDerived,
    "cx.component.capability.derived.v1",
    SdkLatticeKind::OrSet,
    BottomPolicy::Reject,
    Criticality::Required,
    "capability_id",
    &["cx.capability.derived"]
);

per_subject_lattice!(
    SessionGrant,
    "cx.component.session.grant.v1",
    SdkLatticeKind::OrSet,
    BottomPolicy::Reject,
    Criticality::Required,
    "session_id",
    &["cx.session.grant"]
);

per_subject_lattice!(
    DeviceAuthorized,
    "cx.component.device.authorized.v1",
    SdkLatticeKind::OrSet,
    BottomPolicy::Reject,
    Criticality::Required,
    "device_id",
    &["cx.device.authorized", "cx.device.revoked"]
);

per_subject_lattice!(
    DeviceListUpdate,
    "cx.component.device.list_update.v1",
    SdkLatticeKind::OrSet,
    BottomPolicy::Reject,
    Criticality::Required,
    "owner_did",
    &["cx.device.list_update"]
);

// Cross-signing publish / reset — spec `crypto-media/device-lifecycle.md`
// §5.1 / §14.1. The cell key is the principal_id; later publishes MUST
// monotonically advance `generation` and a `cx.cross_signing.reset.v1`
// MUST precede any publish whose generation > previous_accepted.
per_subject_lattice!(
    CrossSigningPublish,
    "cx.component.cross_signing.publish.v1",
    SdkLatticeKind::OrSet,
    BottomPolicy::Reject,
    Criticality::Required,
    "principal_id",
    &["cx.cross_signing.publish.v1", "cx.cross_signing.reset.v1"]
);

// MLS covered_frontier cell — `or-set` of governance-frontier event refs
// each MLS commit attests to. Empty / missing covered_frontier blocks E2EE
// message Moves but not governance Moves (per spec §MLS).
singleton_lattice!(
    CoveredFrontier,
    "cx.component.mls.covered_frontier.v1",
    SdkLatticeKind::OrSet,
    BottomPolicy::Reject,
    Criticality::Required
);

// ────────────────────────── CasRegister families ──────────────────────────
//
// Last-writer-wins on `(hlc, issuer)`; concurrent set → `Bottom::Conflict`
// with both heads exposed. `bottom = reject` for all safety-critical cells:
// the receiver MUST quarantine the cell and emit diagnostics rather than
// pick a winner.

singleton_lattice!(
    SpacePolicy,
    "cx.component.space.policy.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.space.policy"]
);

singleton_lattice!(
    SpaceReadReceiptPolicyLattice,
    "cx.component.space.read_receipt_policy.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.space.read_receipt_policy"]
);

singleton_lattice!(
    SpaceHistoryVisibility,
    "cx.component.space.history_visibility.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.space.history_visibility"]
);

singleton_lattice!(
    SpaceJoinRule,
    "cx.component.space.join_rule.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.space.join_rule"]
);

singleton_lattice!(
    SpaceDiscovery,
    "cx.component.space.discovery.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.space.discovery"]
);

singleton_lattice!(
    SpaceOrganization,
    "cx.component.space.organization.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.space.organization", "cx.space.update"]
);

singleton_lattice!(
    SpaceUpgrade,
    "cx.component.space.upgrade.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.space.upgrade"]
);

singleton_lattice!(
    SpaceArchive,
    "cx.component.space.archive.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.space.archive"]
);

singleton_lattice!(
    SpaceFreeze,
    "cx.component.space.freeze.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.space.freeze"]
);

singleton_lattice!(
    SpaceTombstone,
    "cx.component.space.tombstone.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.space.tombstone"]
);

singleton_lattice!(
    SpaceDestroy,
    "cx.component.space.destroy.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.space.destroy"]
);

singleton_lattice!(
    SpaceModerationPolicy,
    "cx.component.space.moderation_policy.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.space.moderation_policy"]
);

singleton_lattice!(
    SpaceHistorySharingPolicy,
    "cx.component.space.history_sharing_policy.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.space.history_sharing_policy"]
);

singleton_lattice!(
    SpaceAssetPrivacyPolicy,
    "cx.component.space.asset_privacy_policy.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.space.asset_privacy_policy"]
);

singleton_lattice!(
    SpacePolicyComponents,
    "cx.component.space.policy_components.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.space.policy_components"]
);

singleton_lattice!(
    SpacePolicyServer,
    "cx.component.space.policy_server.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.space.policy_server"]
);

singleton_lattice!(
    SpacePlaintextVisibleServices,
    "cx.component.space.plaintext_visible_services.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.space.plaintext_visible_services"]
);

singleton_lattice!(
    SpaceMediaService,
    "cx.component.space.media_service.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.space.media_service"]
);

singleton_lattice!(
    SpaceSchema,
    "cx.component.space.schema.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.space.schema"]
);

singleton_lattice!(
    SpaceInheritancePolicy,
    "cx.component.space.inheritance_policy.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.space.inheritance_policy"]
);

per_subject_lattice!(
    FlowPosition,
    "cx.component.flow.position.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    "flow_id",
    &["cx.flow.move", "cx.flow.reorder"]
);

per_subject_lattice!(
    PlaceParent,
    "cx.component.place.parent.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required,
    "place_id",
    &["cx.place.parent"]
);

// Anchorer cell — singleton `(space_id) → AnchorerValue`. Cas-register so
// concurrent anchorer reconfig from two admins → Bottom (admins MUST coordinate).
singleton_lattice!(
    AnchorerCell,
    "cx.component.anchorer.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required
);

// MLS epoch state — singleton `(space_id) → MlsEpochState`. Cas-register so
// concurrent commit at the same epoch → Bottom (one MUST be a fork).
singleton_lattice!(
    MlsEpoch,
    "cx.component.mls.epoch.v1",
    SdkLatticeKind::CasRegister,
    BottomPolicy::Reject,
    Criticality::Required
);

// ────────────────────────── Fsm families ──────────────────────────
//
// Legal transitions only; illegal transitions surface
// `Bottom::InvalidTransition`. `bottom = reject`.

per_subject_lattice!(
    MemberState,
    "cx.component.member.state.v1",
    SdkLatticeKind::Fsm,
    BottomPolicy::Reject,
    Criticality::Required,
    "actor_id",
    &["cx.member.state"]
);

// ────────────────────────── OrderedLog families ──────────────────────────
//
// Per-issuer monotonic append (issuer_seq). `bottom = reject` — an
// `OrderedLog` rarely surfaces bottom outside replay-protection (duplicate
// issuer_seq).

singleton_lattice!(
    SpaceCreate,
    "cx.component.space.create.v1",
    SdkLatticeKind::OrderedLog,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.space.create"]
);

singleton_lattice!(
    SpaceChild,
    "cx.component.space.child.v1",
    SdkLatticeKind::OrderedLog,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.space.child"]
);

singleton_lattice!(
    SpaceParent,
    "cx.component.space.parent.v1",
    SdkLatticeKind::OrderedLog,
    BottomPolicy::Reject,
    Criticality::Required,
    &["cx.space.parent"]
);

per_subject_lattice!(
    AccountStatus,
    "cx.component.account.status.v1",
    SdkLatticeKind::OrderedLog,
    BottomPolicy::Reject,
    Criticality::Required,
    "account_id",
    &["cx.account.status"]
);

per_subject_lattice!(
    PolicyRule,
    "cx.component.policy.rule.v1",
    SdkLatticeKind::OrderedLog,
    BottomPolicy::Reject,
    Criticality::Required,
    "rule_id",
    &["cx.policy.rule"]
);

// ────────────────────────── MvRegister families ──────────────────────────
//
// Concurrent set → multi-value (heads[]). `bottom = expose` for advisory
// cells (UX renders both candidates), `reject` for safety-critical.

per_subject_lattice!(
    ProfileCreate,
    "cx.component.profile.create.v1",
    SdkLatticeKind::MvRegister,
    BottomPolicy::Expose,
    Criticality::Required,
    "actor_id",
    &["cx.profile.create", "cx.profile.update"]
);

per_subject_lattice!(
    ViewCreate,
    "cx.component.view.create.v1",
    SdkLatticeKind::MvRegister,
    BottomPolicy::Expose,
    Criticality::Required,
    "view_id",
    &["cx.view.create"]
);

per_subject_lattice!(
    ViewUpdate,
    "cx.component.view.update.v1",
    SdkLatticeKind::MvRegister,
    BottomPolicy::Expose,
    Criticality::Required,
    "view_id",
    &["cx.view.update"]
);

per_subject_lattice!(
    ViewReconcile,
    "cx.component.view.reconcile.v1",
    SdkLatticeKind::MvRegister,
    BottomPolicy::Expose,
    Criticality::Required,
    "view_id",
    &["cx.view.reconcile"]
);

per_subject_lattice!(
    MimiRoomBinding,
    "cx.component.mimi.room_binding.v1",
    SdkLatticeKind::MvRegister,
    BottomPolicy::Expose,
    Criticality::Required,
    "room_id",
    &["cx.mimi.room_binding"]
);

// ───────────────────────── Factory ─────────────────────────

/// Build a `LatticeRegistry` pre-populated with every spec-normative cell
/// family covered by this module. Downstream Move/Anchor receive pipelines
/// call this once at boot.
///
/// Coverage target: all 40 unique cell families declared in the spec
/// `event-kind-registry.json`. The remaining niche families need
/// per-subject typed registry support before they can be wired here.
pub fn default_lattice_registry() -> LatticeRegistry {
    let mut registry = LatticeRegistry::new();

    // OrSet
    registry.register(ConsentGrant);
    registry.register(CapabilityGrant);
    registry.register(CapabilityDelegate);
    registry.register(CapabilityDerived);
    registry.register(SessionGrant);
    registry.register(DeviceAuthorized);
    registry.register(DeviceListUpdate);
    registry.register(CrossSigningPublish);
    registry.register(CoveredFrontier);

    // CasRegister
    registry.register(SpacePolicy);
    registry.register(SpaceReadReceiptPolicyLattice);
    registry.register(SpaceHistoryVisibility);
    registry.register(SpaceJoinRule);
    registry.register(SpaceDiscovery);
    registry.register(SpaceOrganization);
    registry.register(SpaceUpgrade);
    registry.register(SpaceArchive);
    registry.register(SpaceFreeze);
    registry.register(SpaceTombstone);
    registry.register(SpaceDestroy);
    registry.register(SpaceModerationPolicy);
    registry.register(SpaceHistorySharingPolicy);
    registry.register(SpaceAssetPrivacyPolicy);
    registry.register(SpacePolicyComponents);
    registry.register(SpacePolicyServer);
    registry.register(SpacePlaintextVisibleServices);
    registry.register(SpaceMediaService);
    registry.register(SpaceSchema);
    registry.register(SpaceInheritancePolicy);
    registry.register(FlowPosition);
    registry.register(PlaceParent);
    registry.register(AnchorerCell);
    registry.register(MlsEpoch);

    // Fsm
    registry.register(MemberState);

    // OrderedLog
    registry.register(SpaceCreate);
    registry.register(SpaceChild);
    registry.register(SpaceParent);
    registry.register(AccountStatus);
    registry.register(PolicyRule);

    // MvRegister
    registry.register(ProfileCreate);
    registry.register(ViewCreate);
    registry.register(ViewUpdate);
    registry.register(ViewReconcile);
    registry.register(MimiRoomBinding);

    registry
}

/// One-shot list of `(cell_family, sdk_lattice_kind, sdk_bottom_mode)`
/// used to bulk-register the SDK's `MemoryCellRegistry` so the
/// Move/Anchor receive pipeline (`apply_anchor` / `verify_move`) resolves
/// every spec-declared cell family correctly. The list mirrors
/// [`default_lattice_registry`] one-to-one.
///
/// Returning a `Vec` (not direct mutation) keeps test assertions easy and
/// lets a future `LatticeKind` impl declare an FSM transition table that
/// would otherwise need a different `register_*` SDK call.
pub fn lattice_bindings_for_sdk_registry() -> Vec<(&'static str, SdkLatticeKind, BottomMode)> {
    let registry = default_lattice_registry();
    // We rely on `default_lattice_registry`'s public surface: iterate every
    // family our soland-side registry knows about. The registry doesn't
    // expose an iterator, so we recompute the family list inline; the
    // canonical source is the spec event-kind-registry — adding a family
    // requires editing both the impl macro call AND this list.
    const FAMILIES: &[&str] = &[
        // OrSet
        "cx.component.consent.grant.v1",
        "cx.component.capability.grant.v1",
        "cx.component.capability.delegate.v1",
        "cx.component.capability.derived.v1",
        "cx.component.session.grant.v1",
        "cx.component.device.authorized.v1",
        "cx.component.device.list_update.v1",
        "cx.component.mls.covered_frontier.v1",
        // CasRegister
        "cx.component.space.policy.v1",
        "cx.component.space.read_receipt_policy.v1",
        "cx.component.space.history_visibility.v1",
        "cx.component.space.join_rule.v1",
        "cx.component.space.discovery.v1",
        "cx.component.space.organization.v1",
        "cx.component.space.upgrade.v1",
        "cx.component.space.archive.v1",
        "cx.component.space.freeze.v1",
        "cx.component.space.tombstone.v1",
        "cx.component.space.destroy.v1",
        "cx.component.space.moderation_policy.v1",
        "cx.component.space.history_sharing_policy.v1",
        "cx.component.space.asset_privacy_policy.v1",
        "cx.component.space.policy_components.v1",
        "cx.component.space.policy_server.v1",
        "cx.component.space.plaintext_visible_services.v1",
        "cx.component.space.media_service.v1",
        "cx.component.space.schema.v1",
        "cx.component.space.inheritance_policy.v1",
        "cx.component.flow.position.v1",
        "cx.component.place.parent.v1",
        "cx.component.anchorer.v1",
        "cx.component.mls.epoch.v1",
        // Fsm
        "cx.component.member.state.v1",
        // OrderedLog
        "cx.component.space.create.v1",
        "cx.component.space.child.v1",
        "cx.component.space.parent.v1",
        "cx.component.account.status.v1",
        "cx.component.policy.rule.v1",
        // MvRegister (bottom=expose)
        "cx.component.profile.create.v1",
        "cx.component.view.create.v1",
        "cx.component.view.update.v1",
        "cx.component.view.reconcile.v1",
        "cx.component.mimi.room_binding.v1",
    ];
    FAMILIES
        .iter()
        .map(|family| {
            let kind = registry
                .lookup(family)
                .unwrap_or_else(|| panic!("default_lattice_registry missing {family}"));
            (
                *family,
                kind.lattice(),
                kind.bottom_policy().to_sdk_bottom_mode(),
            )
        })
        .collect()
}

/// Build a fresh `MemoryCellRegistry` populated with every soland-declared
/// cell family. Move/Anchor receive pipeline (`verify_move` / `apply_anchor`)
/// uses this to resolve `(family → Lattice)` for every effect.
///
/// FSM families (currently just `cx.component.member.state.v1`) need their
/// transition table set via `register_fsm`; the spec-normative membership
/// FSM is encoded inline below.
pub fn build_sdk_cell_registry() -> MemoryCellRegistry {
    use serde_json::json;

    let mut sdk_registry = MemoryCellRegistry::new();
    for (family, kind, bottom_mode) in lattice_bindings_for_sdk_registry() {
        if matches!(kind, SdkLatticeKind::Fsm) {
            // FSM families need explicit transition tables — handled below.
            continue;
        }
        sdk_registry.register(family, kind, bottom_mode);
    }
    // Membership FSM (per spec event-auth-state-resolution.md §5.3): the
    // canonical legal-transition table for `cx.component.member.state.v1`.
    // States match the spec enum: `invite` / `join` / `leave` / `ban` /
    // `knock`. Initial state is `invite`; transitions cover re-entry after
    // leave or ban via a new invite/knock.
    sdk_registry.register_fsm(
        "cx.component.member.state.v1",
        Some(json!("invite")),
        vec![
            // Invitation acceptance / decline.
            (json!("invite"), json!("join")),
            (json!("invite"), json!("leave")),
            // Knock-based join (admin approval) / withdraw.
            (json!("knock"), json!("join")),
            (json!("knock"), json!("leave")),
            // Voluntary departure or admin ban while joined.
            (json!("join"), json!("leave")),
            (json!("join"), json!("ban")),
            // Re-invite / re-knock after voluntary leave.
            (json!("leave"), json!("invite")),
            (json!("leave"), json!("knock")),
            // Bans must be cleared explicitly through a new invite/knock.
            (json!("ban"), json!("invite")),
            (json!("ban"), json!("knock")),
        ],
        BottomMode::Reject,
    );
    sdk_registry
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn default_registry_covers_at_least_all_singleton_cas_families() {
        let registry = default_lattice_registry();
        // Spec event-kind-registry has 40 unique `cell_family` strings, and
        // this registry should cover them all.
        assert!(
            registry.len() >= 40,
            "expected ≥40 cell families registered, got {}",
            registry.len()
        );
    }

    #[test]
    fn consent_grant_has_or_set_lattice_and_consent_id_subject() {
        let registry = default_lattice_registry();
        let kind = registry.lookup("cx.component.consent.grant.v1").unwrap();
        assert_eq!(kind.lattice(), SdkLatticeKind::OrSet);
        assert_eq!(kind.bottom_policy(), BottomPolicy::Reject);
        let payload = json!({"consent_id": "cnt:01HXYZ"});
        let subject = kind.subject_for_effect(&payload).unwrap();
        assert_eq!(subject.as_deref(), Some("cnt:01HXYZ"));
    }

    #[test]
    fn member_state_uses_fsm_lattice_with_actor_subject() {
        let registry = default_lattice_registry();
        let kind = registry.lookup("cx.component.member.state.v1").unwrap();
        assert_eq!(kind.lattice(), SdkLatticeKind::Fsm);
        let payload = json!({"actor_id": "did:example:alice"});
        let subject = kind.subject_for_effect(&payload).unwrap();
        assert_eq!(subject.as_deref(), Some("did:example:alice"));
    }

    #[test]
    fn space_policy_is_singleton_cas_register() {
        let registry = default_lattice_registry();
        let kind = registry.lookup("cx.component.space.policy.v1").unwrap();
        assert_eq!(kind.lattice(), SdkLatticeKind::CasRegister);
        // Singleton: subject is empty even with arbitrary payload.
        let subject = kind.subject_for_effect(&json!({})).unwrap();
        assert!(subject.is_none());
    }

    #[test]
    fn anchorer_cell_is_singleton_cas_register_and_required() {
        let registry = default_lattice_registry();
        let kind = registry.lookup("cx.component.anchorer.v1").unwrap();
        assert_eq!(kind.lattice(), SdkLatticeKind::CasRegister);
        assert_eq!(kind.bottom_policy(), BottomPolicy::Reject);
        let comp = kind.component();
        assert_eq!(comp.criticality, Criticality::Required);
        assert_eq!(comp.component_type, "cx.component.anchorer.v1");
    }

    #[test]
    fn covered_frontier_is_singleton_or_set() {
        let registry = default_lattice_registry();
        let kind = registry
            .lookup("cx.component.mls.covered_frontier.v1")
            .unwrap();
        assert_eq!(kind.lattice(), SdkLatticeKind::OrSet);
        let subject = kind.subject_for_effect(&json!({})).unwrap();
        assert!(subject.is_none());
    }

    #[test]
    fn mv_register_families_have_expose_bottom() {
        let registry = default_lattice_registry();
        for family in [
            "cx.component.profile.create.v1",
            "cx.component.view.create.v1",
            "cx.component.view.update.v1",
            "cx.component.view.reconcile.v1",
            "cx.component.mimi.room_binding.v1",
        ] {
            let kind = registry
                .lookup(family)
                .unwrap_or_else(|| panic!("missing impl for {family}"));
            assert_eq!(kind.lattice(), SdkLatticeKind::MvRegister);
            assert_eq!(
                kind.bottom_policy(),
                BottomPolicy::Expose,
                "{family} should expose multi-value via UX, not reject"
            );
        }
    }

    #[test]
    fn ordered_log_families_have_per_issuer_subject_or_singleton() {
        let registry = default_lattice_registry();
        // Singleton ordered-log
        let kind = registry.lookup("cx.component.space.create.v1").unwrap();
        assert_eq!(kind.lattice(), SdkLatticeKind::OrderedLog);
        // Per-subject ordered-log
        let kind = registry.lookup("cx.component.account.status.v1").unwrap();
        assert_eq!(kind.lattice(), SdkLatticeKind::OrderedLog);
        let payload = json!({"account_id": "act:01HXYZ"});
        let subject = kind.subject_for_effect(&payload).unwrap();
        assert_eq!(subject.as_deref(), Some("act:01HXYZ"));
    }

    #[test]
    fn missing_subject_field_surfaces_typed_error() {
        let registry = default_lattice_registry();
        let kind = registry.lookup("cx.component.flow.position.v1").unwrap();
        let err = kind
            .subject_for_effect(&json!({"unrelated": "x"}))
            .unwrap_err();
        match err {
            LatticeKindError::MissingSubjectField { cell_family, field } => {
                assert_eq!(cell_family, "cx.component.flow.position.v1");
                assert_eq!(field, "flow_id");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn lookup_unknown_family_returns_none() {
        let registry = default_lattice_registry();
        assert!(
            registry
                .lookup("cx.component.does.not.exist.v999")
                .is_none()
        );
    }

    /// Durable event_kind → cell_family inversion. The
    /// LatticeRegistry now indexes `LatticeKind::event_kinds()` so the
    /// lattice-registry apply path can decide whether a given Operation
    /// has a cell-family routing or is a durable-Event-only fallback.
    #[test]
    fn event_kind_index_resolves_consent_grant_and_revoke() {
        let registry = default_lattice_registry();
        let grant = registry
            .lookup_for_event_kind("cx.consent.grant")
            .expect("cx.consent.grant should map to consent.grant.v1 cell");
        assert_eq!(grant.cell_family(), "cx.component.consent.grant.v1");
        let revoke = registry
            .lookup_for_event_kind("cx.consent.revoke")
            .expect("cx.consent.revoke shares the consent.grant.v1 cell (or-set rm)");
        assert_eq!(revoke.cell_family(), "cx.component.consent.grant.v1");
    }

    #[test]
    fn event_kind_index_resolves_membership_to_member_state_cell() {
        let registry = default_lattice_registry();
        let kind = registry
            .lookup_for_event_kind("cx.member.state")
            .expect("cx.member.state should map to member.state.v1 cell");
        assert_eq!(kind.cell_family(), "cx.component.member.state.v1");
    }

    #[test]
    fn event_kind_index_resolves_space_lifecycle() {
        let registry = default_lattice_registry();
        assert_eq!(
            registry
                .lookup_for_event_kind("cx.space.create")
                .unwrap()
                .cell_family(),
            "cx.component.space.create.v1"
        );
        assert_eq!(
            registry
                .lookup_for_event_kind("cx.space.update")
                .unwrap()
                .cell_family(),
            "cx.component.space.organization.v1"
        );
        assert_eq!(
            registry
                .lookup_for_event_kind("cx.space.destroy")
                .unwrap()
                .cell_family(),
            "cx.component.space.destroy.v1"
        );
    }

    #[test]
    fn event_kind_index_misses_durable_only_kinds() {
        let registry = default_lattice_registry();
        // Messages / reactions / read markers / entities don't have a
        // cell_family in the spec — registry must miss; the
        // `apply_via_lattice_registry` path falls through to inline
        // dispatch.
        assert!(
            registry
                .lookup_for_event_kind("cx.message.create")
                .is_none()
        );
        assert!(registry.lookup_for_event_kind("cx.reaction.add").is_none());
    }

    #[test]
    fn event_kind_mappings_count_is_at_least_membership_consent_lifecycle() {
        let registry = default_lattice_registry();
        // 7 membership + 2 consent + 3 space lifecycle = 12 minimum.
        assert!(
            registry.event_kind_mappings() >= 12,
            "expected ≥12 event_kind mappings, got {}",
            registry.event_kind_mappings()
        );
    }
}
