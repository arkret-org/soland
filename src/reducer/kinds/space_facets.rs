//! Per-facet space policy / lifecycle stubs.
//!
//! All singleton-cardinality. Each kind's `project` body is a no-op
//! pending T1-3, but cardinality + component metadata + subject
//! derivation are fully wired.

use crate::reducer::ProjectionEffect;
use crate::reducer::registry::Criticality;

singleton_state_kind!(
    SpacePolicy,
    kind = "cx.space.policy",
    component = "cx.component.space.policy.v1",
    version = 1,
    criticality = Criticality::Required,
    delegate = |_op, _state, _hlc| ProjectionEffect::Ignored,
);

singleton_state_kind!(
    SpaceJoinRule,
    kind = "cx.space.join_rule",
    component = "cx.component.space.join_rule.v1",
    version = 1,
    criticality = Criticality::Required,
    delegate = |_op, _state, _hlc| ProjectionEffect::Ignored,
);

singleton_state_kind!(
    SpaceHistoryVisibility,
    kind = "cx.space.history_visibility",
    component = "cx.component.space.history_visibility.v1",
    version = 1,
    criticality = Criticality::Required,
    delegate = |_op, _state, _hlc| ProjectionEffect::Ignored,
);

singleton_state_kind!(
    SpaceDiscovery,
    kind = "cx.space.discovery",
    component = "cx.component.space.discovery.v1",
    version = 1,
    criticality = Criticality::Required,
    delegate = |_op, _state, _hlc| ProjectionEffect::Ignored,
);

singleton_state_kind!(
    SpacePolicyServer,
    kind = "cx.space.policy_server",
    component = "cx.component.space.policy_server.v1",
    version = 1,
    criticality = Criticality::Required,
    delegate = |_op, _state, _hlc| ProjectionEffect::Ignored,
);

singleton_state_kind!(
    SpacePolicyComponents,
    kind = "cx.space.policy_components",
    component = "cx.component.space.policy_components.v1",
    version = 1,
    criticality = Criticality::Required,
    delegate = |_op, _state, _hlc| ProjectionEffect::Ignored,
);

singleton_state_kind!(
    SpaceHistorySharingPolicy,
    kind = "cx.space.history_sharing_policy",
    component = "cx.component.space.history_sharing_policy.v1",
    version = 1,
    criticality = Criticality::Required,
    delegate = |_op, _state, _hlc| ProjectionEffect::Ignored,
);

singleton_state_kind!(
    SpaceAssetPrivacyPolicy,
    kind = "cx.space.asset_privacy_policy",
    component = "cx.component.space.asset_privacy_policy.v1",
    version = 1,
    criticality = Criticality::Required,
    delegate = |_op, _state, _hlc| ProjectionEffect::Ignored,
);

singleton_state_kind!(
    SpaceModerationPolicy,
    kind = "cx.space.moderation_policy",
    component = "cx.component.space.moderation_policy.v1",
    version = 1,
    criticality = Criticality::Required,
    delegate = |_op, _state, _hlc| ProjectionEffect::Ignored,
);

singleton_state_kind!(
    SpacePlaintextVisibleServices,
    kind = "cx.space.plaintext_visible_services",
    component = "cx.component.space.plaintext_visible_services.v1",
    version = 1,
    criticality = Criticality::Required,
    delegate = |_op, _state, _hlc| ProjectionEffect::Ignored,
);

singleton_state_kind!(
    SpaceMediaService,
    kind = "cx.space.media_service",
    component = "cx.component.space.media_service.v1",
    version = 1,
    criticality = Criticality::Required,
    delegate = |_op, _state, _hlc| ProjectionEffect::Ignored,
);

singleton_state_kind!(
    SpaceSchema,
    kind = "cx.space.schema",
    component = "cx.component.space.schema.v1",
    version = 1,
    criticality = Criticality::Required,
    delegate = |_op, _state, _hlc| ProjectionEffect::Ignored,
);

singleton_state_kind!(
    SpaceArchive,
    kind = "cx.space.archive",
    component = "cx.component.space.archive.v1",
    version = 1,
    criticality = Criticality::Required,
    delegate = |_op, _state, _hlc| ProjectionEffect::Ignored,
);

singleton_state_kind!(
    SpaceFreeze,
    kind = "cx.space.freeze",
    component = "cx.component.space.freeze.v1",
    version = 1,
    criticality = Criticality::Required,
    delegate = |_op, _state, _hlc| ProjectionEffect::Ignored,
);

singleton_state_kind!(
    SpaceTombstone,
    kind = "cx.space.tombstone",
    component = "cx.component.space.tombstone.v1",
    version = 1,
    criticality = Criticality::Required,
    delegate = |_op, _state, _hlc| ProjectionEffect::Ignored,
);
